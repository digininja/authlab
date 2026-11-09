function loadToken(elementId, event) {
    if (event) {
        event.preventDefault();
    }

    var src = document.getElementById(elementId);
    var dest = document.getElementById('jwt');

    if (src && dest) {
        dest.value = src.value.trim();
    }
}

document.addEventListener("DOMContentLoaded", function () {
    var buttonBob = document.getElementById("button_bob");
    if (buttonBob) {
        buttonBob.addEventListener("click", (event) => loadToken("token_bob", event));
    }

    var buttonAlice = document.getElementById("button_alice");
    if (buttonAlice) {
        buttonAlice.addEventListener("click", (event) => loadToken("token_alice", event));
    }
});
