
function createCORSRequest(method, url) {
	var xhr = new XMLHttpRequest();
	if ("withCredentials" in xhr) {
		// Check if the XMLHttpRequest object has a "withCredentials" property.
		// "withCredentials" only exists on XMLHTTPRequest2 objects.
		xhr.open(method, url, true);
	} else if (typeof XDomainRequest != "undefined") {
		// Otherwise, check if XDomainRequest.
		// XDomainRequest only exists in IE, and is IE's way of making CORS requests.
		xhr = new XDomainRequest();
		xhr.open(method, url);
	} else {
		// Otherwise, CORS is not supported by the browser.
		xhr = null;
	}
	return xhr;
}

function jwt_none_request () {
	var url = "/JWT_None_Check"

	var xhr = createCORSRequest('GET', url);
	if (!xhr) {
		throw new Error('CORS not supported');
	}

	xhr.setRequestHeader ("Authorization", "Bearer: aaa");

	xhr.onload = function() {
		var responseText = xhr.responseText;
		// console.log("Response from basic GET request: " + responseText);
		console.log ("Server says: " + responseText);
	};

	xhr.onerror = function() {
		console.log('Error: GET request made with extra header which is allowed.');
	};

	xhr.send()
}
