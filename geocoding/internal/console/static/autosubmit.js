// Submits the SAML HTTP-POST binding form (saml_post.html). Without
// JavaScript the page's Continue button does the same.
(function () {
  "use strict";
  var f = document.getElementById("saml-autosubmit");
  if (f) {
    f.submit();
  }
})();
