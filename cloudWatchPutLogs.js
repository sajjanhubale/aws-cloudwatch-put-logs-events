// AWS Version 4 signing example

// Translate API (TranslateText)

// For more information about using Signature Version 4, see http://docs.aws.amazon.com/general/latest/gr/sigv4_signing.html.
// This example makes a POST request to Amazon Translate and
// passes the text to translate JSON in the body (payload)
// of the request. Authentication information is passed in an
// Authorization header.
var crypto = require("crypto-js");
var request = require("request");
const curDate = new Date();
// import requests // pip install requests

// ************* REQUEST VALUES *************
const method = "POST";
const service = "logs";
const region = "us-east-1";
const host = service + "." + region + ".amazonaws.com";
const endpoint = "https://" + host + "/";

// POST requests use a content type header. For Amazon Translate,
// the content is JSON.
const content_type = "application/x-amz-json-1.1";
// Amazon Translate requires an x-amz-target header that has this format:
//     AWSShineFrontendService_20170701.<operationName>.
const amz_target = "Logs_20140328.PutLogEvents";

// Pass request parameters for the TranslateText operation in a JSON block.
// request_parameters =  '{'
// request_parameters +=  '"Text": "Hello world.",'
// request_parameters +=  '"SourceLanguageCode": "en",'
// request_parameters +=  '"TargetLanguageCode": "de"'
// request_parameters +=  '}'

// The following functions derive keys for the request. For more information, see
// https://docs.aws.amazon.com/general/latest/gr/signature-v4-examples.html#signature-v4-examples-javascript
function getSignatureKey(key, dateStamp, regionName, serviceName) {
  var kDate = crypto.HmacSHA256(dateStamp, "AWS4" + key);
  var kRegion = crypto.HmacSHA256(regionName, kDate);
  var kService = crypto.HmacSHA256(serviceName, kRegion);
  var kSigning = crypto.HmacSHA256("aws4_request", kService);
  return kSigning;
}

// this function converts the generic JS ISO8601 date format to the specific format the AWS API wants
function getAmzDate(dateStr) {
  var chars = [":", "-"];
  for (var i = 0; i < chars.length; i++) {
    while (dateStr.indexOf(chars[i]) != -1) {
      dateStr = dateStr.replace(chars[i], "");
    }
  }
  dateStr = dateStr.split(".")[0] + "Z";
  return dateStr;
}

// embed credentials in code.
const access_key = process.env.ACCESS_KEY;
const secret_key = process.env.SECRET_KEY;
var amz_date = getAmzDate(curDate.toISOString());
var date_stamp = amz_date.split("T")[0];
// Create a timestamp for headers and the credential string.
// ************* TASK 1: CREATE A CANONICAL REQUEST *************
// For information about creating a canonical request, see http://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html.

// Step 1: Define the verb (GET, POST, etc.), which you have already done.

// Step 2: Create a canonical URI. A canonical URI is the part of the URI from domain to query.
// string (use '/' if no path)
const canonical_uri = "/";

// Step 3: Create the canonical query string. In this example, request
// parameters are passed in the body of the request and the query string
// is blank.
const canonical_querystring = "";

// Step 4: Create the canonical headers. Header names must be trimmed,
// lowercase, and sorted in code point order from low to high.
// Note the trailing \n.
const canonical_headers =
  "content-type:" +
  content_type +
  "\n" +
  "host:" +
  host +
  "\n" +
  "x-amz-date:" +
  amz_date +
  "\n" +
  "x-amz-target:" +
  amz_target +
  "\n";

// Step 5: Create the list of signed headers by listing the headers
// in the canonical_headers list, delimited with ";" and in alphabetical order.
// Note: The request can include any headers. Canonical_headers and
// signed_headers should contain headers to include in the hash of the
// request. "Host" and "x-amz-date" headers are always required.
// For Amazon Translate, content-type and x-amz-target are also required.
const signed_headers = "content-type;host;x-amz-date;x-amz-target";

// Step 6: Create the payload hash. In this example, the request_parameters
// variable contains the JSON request parameters.
// we have an empty payload here because it is a GET request
const payload = JSON.stringify({
  logGroupName: "test",
  logStreamName: "test1",
  logEvents: [
    {
      timestamp: curDate.getTime(),
      message: "abc",
    },
  ],
  sequenceToken: "49612626900961529812397345948731325330668107926203873250",
});
const payload_hash = crypto.SHA256(payload).toString();

// Step 7: Combine the elements to create a canonical request.
const canonical_request =
  method +
  "\n" +
  canonical_uri +
  "\n" +
  canonical_querystring +
  "\n" +
  canonical_headers +
  "\n" +
  signed_headers +
  "\n" +
  payload_hash;

// ************* TASK 2: CREATE THE STRING TO SIGN*************
// Set the algorithm variable to match the hashing algorithm that you use, either SHA-256 (recommended) or SHA-1.
//
const algorithm = "AWS4-HMAC-SHA256";
const credential_scope =
  date_stamp + "/" + region + "/" + service + "/" + "aws4_request";
const string_to_sign =
  algorithm +
  "\n" +
  amz_date +
  "\n" +
  credential_scope +
  "\n" +
  crypto.SHA256(canonical_request).toString();

// ************* TASK 3: CALCULATE THE SIGNATURE *************
// Create the signing key using the getSignaturKey function defined above.
const signing_key = getSignatureKey(secret_key, date_stamp, region, service);

// Sign the string_to_sign using the signing_key.
const signature = crypto.HmacSHA256(string_to_sign, signing_key);

// ************* TASK 4: ADD SIGNING INFORMATION TO THE REQUEST *************
// Put the signature information in a header named Authorization.
const authorization_header =
  algorithm +
  " " +
  "Credential=" +
  access_key +
  "/" +
  credential_scope +
  ", " +
  "SignedHeaders=" +
  signed_headers +
  ", " +
  "Signature=" +
  signature;

// For Amazon Translate, the request can include any headers, but it must include "host," "x-amz-date,"
// "x-amz-target," "content-type," and "Authorization" headers. Except for the authorization
// header, the headers must be included in the canonical_headers and signed_headers values, as
// noted earlier. Header order is not significant.
const headers = {
  "Content-Type": content_type,
  "X-Amz-Date": amz_date,
  "X-Amz-Target": amz_target,
  Authorization: authorization_header,
};

// ************* TASK 5: SEND THE REQUEST *************
var options = {
  method: "POST",
  url: endpoint,
  headers,
  body: payload,
};
request(options, function (error, response) {
  if (error) throw new Error(error);
  console.log(response.body);
});
