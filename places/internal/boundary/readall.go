package boundary

import (
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"strings"
)

// ReadAll reads every record from the shapefile into Locality records.
// The .shp records are read sequentially by record header (each starts with
// an 8-byte header: record number + content length in 16-bit words). The
// .dbf records are read as fixed-width rows. Both counts must agree.
func (r *Reader) ReadAll() ([]Locality, error) {
	var out []Locality
	// Read .shp record headers to know payload lengths. We read record-by-record
	// using the 8-byte header to get the content length, then read the payload.
	// The .shp file position is right after the 100-byte header.
	shpPos := int64(100)
	// Seek to the start of shp records (after the 100-byte header).
	if _, err := r.shp.Seek(shpPos, io.SeekStart); err != nil {
		return nil, fmt.Errorf("shp seek records: %w", err)
	}
	recNum := 0
	for recNum < r.records {
		// Read the 8-byte record header.
		hdr := make([]byte, 8)
		if _, err := io.ReadFull(r.shp, hdr); err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("shp record %d header: %w", recNum, err)
		}
		contentLen := int(binary.BigEndian.Uint32(hdr[4:8])) * 2 // words -> bytes
		payload := make([]byte, contentLen)
		if _, err := io.ReadFull(r.shp, payload); err != nil {
			return nil, fmt.Errorf("shp record %d payload: %w", recNum, err)
		}

		// Parse the polygon payload.
		poly, err := parsePolygon(payload)
		if err != nil {
			return nil, fmt.Errorf("shp record %d polygon: %w", recNum, err)
		}

		// Read the matching .dbf record.
		dbfRec := make([]byte, r.recLen)
		if _, err := io.ReadFull(r.dbf, dbfRec); err != nil {
			return nil, fmt.Errorf("dbf record %d: %w", recNum, err)
		}
		attrs := decodeDBF(dbfRec, r.fields)

		out = append(out, Locality{
			Polygon:   poly,
			LocPID:    attrs["LOC_PID"],
			Name:      attrs["LOC_NAME"],
			LocClass:  attrs["LOC_CLASS"],
			State:     attrs["STATE"],
			ShapeType: ShapeTypePolygon,
		})
		recNum++
	}
	return out, nil
}

// parsePolygon parses a shape type 5 (polygon) payload. The payload layout:
// int32 shapeType, 4x float64 bbox (Xmin,Ymin,Xmax,Ymax), int32 numParts,
// int32 numPoints, numParts x int32 part start indices, numPoints x 2 float64.
func parsePolygon(p []byte) (Polygon, error) {
	if len(p) < 44 {
		return Polygon{}, fmt.Errorf("polygon payload too short: %d", len(p))
	}
	st := int(binary.LittleEndian.Uint32(p[0:4]))
	if st != ShapeTypePolygon {
		return Polygon{}, fmt.Errorf("shape type %d, expected polygon", st)
	}
	bbox := [4]float64{
		Float64(p[4:12]), Float64(p[12:20]), Float64(p[20:28]), Float64(p[28:36]),
	}
	numParts := int(binary.LittleEndian.Uint32(p[36:40]))
	numPoints := int(binary.LittleEndian.Uint32(p[40:44]))
	off := 44
	parts := make([]int, numParts)
	for i := 0; i < numParts; i++ {
		parts[i] = int(binary.LittleEndian.Uint32(p[off : off+4]))
		off += 4
	}
	points := make([]Point, numPoints)
	for i := 0; i < numPoints; i++ {
		points[i] = Point{Float64(p[off : off+8]), Float64(p[off+8 : off+16])}
		off += 16
	}

	// Split the flat points into rings per the part start indices.
	rings := make([][]Point, numParts)
	for pi := 0; pi < numParts; pi++ {
		start := parts[pi]
		end := numPoints
		if pi+1 < numParts {
			end = parts[pi+1]
		}
		if start > len(points) || end > len(points) || start > end {
			return Polygon{}, fmt.Errorf("invalid part bounds %d..%d of %d points", start, end, len(points))
		}
		rings[pi] = points[start:end]
	}
	return Polygon{Parts: rings, BBox: bbox}, nil
}

// Float64 reads a little-endian float64 from b.
func Float64(b []byte) float64 {
	return math.Float64frombits(binary.LittleEndian.Uint64(b))
}

// decodeDBF parses one fixed-width dBase record into a map of field name -> value.
func decodeDBF(rec []byte, fields []field) map[string]string {
	// Record starts with a deletion flag byte (offset 0); data follows.
	// Field values are at fixed offsets. We track the offset as we go.
	off := 1 // skip deletion flag
	vals := make(map[string]string, len(fields))
	for _, f := range fields {
		end := off + f.length
		if end > len(rec) {
			end = len(rec)
		}
		v := strings.TrimRight(string(rec[off:end]), "\x00\x20")
		vals[f.name] = v
		off = end
	}
	return vals
}
