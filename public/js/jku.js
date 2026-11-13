function loadToken(sourceId, event) {
    if (event) {
        event.preventDefault();
    }
    var src = document.getElementById(sourceId);
    var dest = document.getElementById("jwt");
    if (src && dest) {
        dest.value = src.value.trim();
    }
}

document.addEventListener("DOMContentLoaded", function () {
    var loadBtn = document.getElementById("button_load_sample");
    if (loadBtn) {
        loadBtn.addEventListener("click", (e) => loadToken("token_sample", e));
    }
});
