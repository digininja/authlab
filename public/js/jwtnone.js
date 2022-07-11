function validate_token () {
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
		if (xhr.readyState == 4 && xhr.status == 200) {
			console.log ("Server says: " + xhr.responseText);

			let jsonObj = JSON.parse(xhr.responseText);
			if (jsonObj.Success) {
				document.getElementById("header").style.color = "green";
				document.getElementById("header").innerText = "Login Success";
				document.getElementById("user").innerText = "User: " + jsonObj.User;
				document.getElementById("level").innerText = "Level: " + jsonObj.Level;
				document.getElementById("user").style.display = "block";
				document.getElementById("level").style.display = "block";
				document.getElementById("error").style.display = "none";
			} else {
				document.getElementById("header").style.color = "red";
				document.getElementById("header").innerText = "Login Failed";
				document.getElementById("error").innerText = "Error: " + jsonObj.Message;
				document.getElementById("user").style.display = "none";
				document.getElementById("level").style.display = "none";
				document.getElementById("error").style.display = "block";
			}
		} else {
			console.log ("There was a problem with the reply from the server");
		}
	};

	xhr.onerror = function() {
		console.log('Error making request');
	};

	xhr.send()
}

var button = document.getElementById ("validate_token");
button.addEventListener("click", validate_token);
