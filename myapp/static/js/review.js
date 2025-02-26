document.addEventListener("DOMContentLoaded", function () {
    console.log("✅ JavaScript Loaded: review.js");

    let reviewedProducts = JSON.parse(localStorage.getItem("reviewedProducts") || "{}");
    console.log("🔍 DEBUG: Loaded Reviewed Products ->", reviewedProducts);

    document.querySelectorAll(".review-btn").forEach(button => {
        let orderId = button.dataset.orderId;
        let productId = button.dataset.productId;
        let key = `${productId}_${orderId}`;

        // ✅ ตรวจสอบว่ารีวิวไปแล้วหรือไม่
        if (reviewedProducts[key]) {
            button.textContent = "✅ รีวิวแล้ว";
            button.classList.remove("btn-primary");
            button.classList.add("btn-secondary");
            button.disabled = true;
        }

        // ✅ เมื่อกดปุ่มรีวิว ให้บันทึกสถานะรีวิวใน localStorage
        button.addEventListener("click", function () {
            reviewedProducts[key] = true;
            localStorage.setItem("reviewedProducts", JSON.stringify(reviewedProducts));
        });
    });
});

