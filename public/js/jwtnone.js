function jwt_none_request () {
	var url = "/JWT_None_Check"

	let xhr = new XMLHttpRequest();
	xhr.open("GET", url, true);
	if (!xhr) {
		throw new Error('XMLHttpRequest not supported');
	}

	// JWT with none
	// let token = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJsZXZlbCI6InVzZXIiLCJ1c2VyIjoic2lkIn0."
	let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoicm9iaW4iLCJsZXZlbCI6InVzZXIifQ.oYPuxIPnm6lYx3Zx_8zaMGVw7Np5nZtgJVnaMqlZcOQ"

	xhr.setRequestHeader ("Authorization", "Bearer " + token);

	xhr.onload = function() {
		var responseText = xhr.responseText;
		console.log ("Server says: " + responseText);
	};

	xhr.onerror = function() {
		console.log('Error making request');
	};

	xhr.send()
}
