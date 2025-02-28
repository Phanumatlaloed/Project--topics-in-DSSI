document.addEventListener("DOMContentLoaded", function () {
    document.addEventListener("click", function (event) {
        if (event.target.classList.contains("edit-comment")) {
            let commentId = event.target.getAttribute("data-comment-id");
            let commentElement = document.querySelector(`#comment-${commentId} .comment-content`);

            if (commentElement) {
                let currentText = commentElement.textContent;
                let inputField = document.createElement("input");
                inputField.type = "text";
                inputField.value = currentText;
                inputField.classList.add("form-control");
                inputField.style.width = "80%";

                let saveButton = document.createElement("button");
                saveButton.textContent = "✔ Save";
                saveButton.classList.add("btn", "btn-success", "btn-sm", "ms-2");

                let parentDiv = commentElement.parentElement;
                parentDiv.innerHTML = "";
                parentDiv.appendChild(inputField);
                parentDiv.appendChild(saveButton);

                saveButton.addEventListener("click", function () {
                    let newText = inputField.value;
                    
                    fetch(`/edit_comment/${commentId}/`, {
                        method: "POST",
                        headers: {
                            "Content-Type": "application/json",
                            "X-CSRFToken": getCSRFToken(),
                        },
                        body: JSON.stringify({ content: newText }),
                    })
                    .then(response => response.json())
                    .then(data => {
                        if (data.success) {
                            parentDiv.innerHTML = `<b>${data.username}</b>: <span class="comment-content">${newText}</span>`;
                        } else {
                            alert("❌ แก้ไขไม่สำเร็จ!");
                        }
                    })
                    .catch(error => console.error("❌ Error:", error));
                });
            }
        }
    });

    function getCSRFToken() {
        return document.querySelector("[name=csrfmiddlewaretoken]").value;
    }

    // ✅ ลบไฟล์ที่อัปโหลดแล้ว
    document.querySelectorAll(".remove-existing-file").forEach((button) => {
        button.addEventListener("click", function () {
            const mediaId = this.getAttribute("data-file-id");

            fetch(`/delete_media/${mediaId}/`, {
                method: "DELETE",
                headers: {
                    "X-CSRFToken": getCSRFToken(),
                    "X-Requested-With": "XMLHttpRequest"
                }
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    this.parentElement.remove();
                } else {
                    console.error("❌ Failed to delete:", data.error);
                }
            })
            .catch(error => console.error("❌ AJAX Error:", error));
        });
    });

    function getCSRFToken() {
        return document.querySelector("[name=csrfmiddlewaretoken]").value;
    }
});
