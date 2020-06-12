
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

	// With
	// let token = "eyJhbGciOiJSUzI1NiIsInR5cCI6ImF0K0pXVCIsImtpZCI6IjIwMTkwNzMwLTU0ZmY5NTZlIn0.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmZpcmVmb3guY29tIiwiYXVkIjoiNTg4MjM4NmM2ZDgwMTc3NiIsImNsaWVudF9pZCI6IjU4ODIzODZjNmQ4MDE3NzYiLCJleHAiOjE1OTIxNjc5MDQsImlhdCI6MTU5MTk5NTEwNCwianRpIjoiMTY5OWVhM2ZiNjQ0NjBiMTRjM2I3NDg1NjdhMDQ5NjAxZjg4ZjQxOGJhMDVkZDIyMDdkMjk3YjUwNzBmM2Y4NiIsInNjb3BlIjoic3luYzphZGRvbl9zdG9yYWdlIiwic3ViIjoiOTY5NmQ2NDlmMWViNDA4ZDk2ODc2YmVhZGVmNGJkMmEiLCJmeGEtZ2VuZXJhdGlvbiI6MTQ5NzQzMDA1NDQ4MywiZnhhLXByb2ZpbGVDaGFuZ2VkQXQiOjE0OTc0MzAwNTQ0ODN9.ThTSZFka4yQjCEqktN12rkfBgOp5WLcQqs5IqudmOWsCZA4Qn4SLBCLxQGapzfiiZ5P2gKebZWzSqY6-QIfojadKWC6XEDQruDIg5yH5cJSjXJi3fDh4e8BSg_X867eHf9-mAtblgdJfCeTZ58q6LjUU2i1p71kzUkosYRtF-u-9BeLHlfGvgE5PzfsriOrRU2V6bLSy1XE06FPfICGaTMur-x0OF8SG0zzRUzIcD0KT6VdjmLgN2_iSdIS26k6PFzKvk01iLPBHAmIE_-2YjvwhHSRefCtjOC4wihra9nhj22O9P6ifQpo7k4HfMdOMrDyrMLVlVHyOFaKkEymuGQ"

	// JWT with none
	let token = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJsZXZlbCI6InVzZXIiLCJ1c2VyIjoic2lkIn0."

	xhr.setRequestHeader ("Authorization", "Bearer " + token);

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
