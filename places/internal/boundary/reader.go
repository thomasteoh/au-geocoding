// Package boundary reads Geoscape Administrative Boundaries Locality shapefiles
// and loads the polygons into the serving DB's geopoly index.
//
// The .shp reader is self-contained (stdlib only): the format is a fixed
// 100-byte header followed by records, each with an 8-byte record header and
// a shape payload. Shape type 5 = polygon. The .dbf reader is dBase III:
// a header (32 bytes + N field descriptors) followed by fixed-width records.
// Both are simple binary formats with no external dependency needed.
package boundary

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// ShapeType constants from the ESRI shapefile spec.
const (
	ShapeTypeNull     = 0
	ShapeTypePolygon  = 5
	ShapeTypePolyLine = 3
)

// Point is an X/Y coordinate pair.
type Point struct{ X, Y float64 }

// Polygon is a set of rings (parts); parts[0] is the outer ring, later parts
// are holes or islands. GeoJSON needs one polygon per outer ring with holes
// as interior rings, which we emit as separate geopoly rows.
type Polygon struct {
	Parts [][]Point
	BBox  [4]float64
}

// Locality is one shapefile record: the polygon geometry plus the DBF
// attributes (locality_pid, name, class, state).
type Locality struct {
	Polygon   Polygon
	LocPID    string
	Name      string
	LocClass  string
	State     string
	ShapeType int
}

// Reader reads a .shp/.dbf pair into Locality records. Both files must have
// the same record count.
type Reader struct {
	shp     *os.File
	dbf     *os.File
	records int
	fields  []field
	recLen  int
	hdrLen  int
}

type field struct {
	name   string
	typ    byte
	length int
}

// Open reads the shapefile headers and validates the format.
func Open(shpPath, dbfPath string) (*Reader, error) {
	shp, err := os.Open(shpPath)
	if err != nil {
		return nil, fmt.Errorf("open shp: %w", err)
	}
	hdr := make([]byte, 100)
	if _, err := io.ReadFull(shp, hdr); err != nil {
		shp.Close()
		return nil, fmt.Errorf("shp header: %w", err)
	}
	// Validate file code 9994 big-endian and shape type.
	code := binary.BigEndian.Uint32(hdr[0:4])
	if code != 9994 {
		shp.Close()
		return nil, fmt.Errorf("shp file code %d != 9994", code)
	}
	fileLen := int(binary.BigEndian.Uint32(hdr[24:28]))
	shapeType := int(binary.LittleEndian.Uint32(hdr[32:36]))
	if shapeType != ShapeTypePolygon {
		shp.Close()
		return nil, fmt.Errorf("shape type %d, expected %d (polygon)", shapeType, ShapeTypePolygon)
	}
	// Count records from file length: 100 header + 8 per record header + payload.
	// We can't know payload size without scanning, so count via the record
	// headers on the fly in ReadAll.
	_ = fileLen

	dbf, err := os.Open(dbfPath)
	if err != nil {
		shp.Close()
		return nil, fmt.Errorf("open dbf: %w", err)
	}
	dbhdr := make([]byte, 32)
	if _, err := io.ReadFull(dbf, dbhdr); err != nil {
		shp.Close()
		dbf.Close()
		return nil, fmt.Errorf("dbf header: %w", err)
	}
	nrec := int(binary.LittleEndian.Uint32(dbhdr[4:8]))
	hdrLen := int(binary.LittleEndian.Uint16(dbhdr[8:10]))
	recLen := int(binary.LittleEndian.Uint16(dbhdr[10:12]))
	nFields := (hdrLen - 32) / 32

	fields := make([]field, nFields)
	desc := make([]byte, 32)
	for i := 0; i < nFields; i++ {
		if _, err := io.ReadFull(dbf, desc); err != nil {
			shp.Close()
			dbf.Close()
			return nil, fmt.Errorf("dbf field %d: %w", i, err)
		}
		fields[i] = field{
			name:   strings.TrimRight(string(desc[0:11]), "\x00"),
			typ:    desc[11],
			length: int(desc[16]),
		}
	}
	// Skip to first record.
	if _, err := dbf.Seek(int64(hdrLen), io.SeekStart); err != nil {
		shp.Close()
		dbf.Close()
		return nil, fmt.Errorf("dbf seek: %w", err)
	}

	return &Reader{shp: shp, dbf: dbf, records: nrec, fields: fields, recLen: recLen, hdrLen: hdrLen}, nil
}

// Close closes both files.
func (r *Reader) Close() error {
	var errs []error
	if r.shp != nil {
		if err := r.shp.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if r.dbf != nil {
		if err := r.dbf.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// recLen and hdrLen are stored on the reader; add to the struct.
// (Declared below via the struct literal in Open.)
