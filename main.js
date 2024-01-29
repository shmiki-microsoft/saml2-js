var saml2 = require('saml2-js');
var fs = require('fs');
var express = require('express');
var app = express();
// If you're using express <4.0:
// var bodyParser = require('body-parser');
// app.use(bodyParser.urlencoded({
//   extended: true
// }));
//app.use(express.urlencoded());
app.use(express.urlencoded({ extended: true }));

// Create service provider
var sp_options = {
  entity_id: process.env.SP_ENTITY_ID,
  private_key: fs.readFileSync(`keys/SP/${process.env.SP_PRIVATE_KEY_FILE}`).toString(),
  certificate: fs.readFileSync(`keys/SP/${process.env.SP_CERT_FILE}`).toString(),
  assert_endpoint: process.env.SP_ASSERT_ENDPOINT,
  allow_unencrypted_assertion: true,
  //sign_get_request: true
};
var sp = new saml2.ServiceProvider(sp_options);

// Create identity provider
var idp_options = {
  sso_login_url: process.env.IDP_SSO_LOGIN_URL,
  sso_logout_url: process.env.IDP_SSO_LOGOUT_URL,
  certificates: [fs.readFileSync(`keys/IdP/${process.env.IDP_CERT_FILE}`).toString()]
};
var idp = new saml2.IdentityProvider(idp_options);

// ------ Define express endpoints ------
app.get("/", function(req, res) {
  res.send('<p>Please login at <a href="/login">/login</a></p>');
});

// Endpoint to retrieve metadata
app.get("/metadata.xml", function(req, res) {
  res.type('application/xml');
  res.send(sp.create_metadata());
});

// Starting point for login
app.get("/login", function(req, res) {
  sp.create_login_request_url(idp, {}, function(err, login_url, request_id) {
    if (err != null)
      return res.send(500);
    res.redirect(login_url);
  });
});

// Variables used in login/logout process
var name_id, session_index;

// Assert endpoint for when login completes
app.post("/assert", function(req, res) {
  var options = {request_body: req.body};
  sp.post_assert(idp, options, function(err, saml_response) {
    if (err != null)
      return res.send(500);

    // Save name_id and session_index for logout
    // Note:  In practice these should be saved in the user session, not globally.
    name_id = saml_response.user.name_id;
    session_index = saml_response.user.session_index;

    res.send(`Hello ${name_id}! session_index: ${session_index}.\n <a href="/logout">logout</a></p>`);
  });
});

// Starting point for logout
app.get("/logout", function(req, res) {
  var options = {
    name_id: name_id,
    session_index: session_index
  };

  sp.create_logout_request_url(idp, options, function(err, logout_url) {
    if (err != null)
      return res.send(500);
    res.redirect(logout_url);
  });
});

//start app server to listen on set port
const port = process.env.PORT || process.env.SERVER_PORT
app.listen(port, () => console.log(`saml2-js Sample app listening on port !` + port));