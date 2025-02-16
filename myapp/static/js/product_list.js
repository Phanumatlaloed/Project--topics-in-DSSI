// ✅ ฟังก์ชันดึง CSRF Token จาก Cookies
function getCSRFToken() {
    let cookieValue = null;
    if (document.cookie && document.cookie !== "") {
        const cookies = document.cookie.split(";");
        for (let i = 0; i < cookies.length; i++) {
            const cookie = cookies[i].trim();
            if (cookie.startsWith("csrftoken=")) {
                cookieValue = cookie.substring("csrftoken=".length, cookie.length);
                break;
            }
        }
    }
    return cookieValue;
}

document.addEventListener("DOMContentLoaded", function() {
    document.querySelectorAll(".add-to-cart-btn").forEach(button => {
        button.addEventListener("click", function(event) {
            event.preventDefault();
            let productId = this.getAttribute("data-product-id");

            fetch(`/cart/add/${productId}/`, {
                method: "POST",
                headers: {
                    "X-CSRFToken": getCSRFToken(), // ✅ ใช้ฟังก์ชันดึง CSRF Token
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({})
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    document.getElementById("cart-count").innerText = data.cart_count;
                    alert("✅ สินค้าถูกเพิ่มลงในตะกร้าแล้ว!");
                } else {
                    alert("⚠️ เกิดข้อผิดพลาด: " + data.message);
                }
            })
            .catch(error => console.error("Error:", error));
        });
    });
});