document.addEventListener("DOMContentLoaded", function () {
    console.log("✅ JavaScript Loaded: review.js");

    // ✅ โหลดข้อมูลรีวิวจาก Django ที่ฝังไว้ใน HTML
    let reviewedProductsRaw = document.getElementById("reviewed-products-data")?.value || "{}";
    let reviewedProducts = {};

    try {
        reviewedProducts = JSON.parse(reviewedProductsRaw);
    } catch (error) {
        console.error("❌ JSON Parsing Error:", error);
        reviewedProducts = {};
    }

    console.log("🔍 Reviewed Products from Django ->", reviewedProducts);

    // ✅ ตรวจสอบปุ่มรีวิวและอัปเดตสถานะ
    document.querySelectorAll(".review-btn").forEach(button => {
        const orderId = button.dataset.orderId;
        const productId = button.dataset.productId;
        const key = `${productId}_${orderId}`;

        console.log(`🔍 Checking review-btn key: ${key}, reviewed: ${reviewedProducts[key]}`);

        if (reviewedProducts[key]) {
            button.textContent = "✅ รีวิวแล้ว";
            button.classList.remove("btn-primary");
            button.classList.add("btn-secondary");
            button.disabled = true;
        }
    });

    // ✅ อัปเดตปุ่มขอคืนเงิน
    updateRefundButtons(reviewedProducts);

    function updateRefundButtons(reviewedProducts) {
        document.querySelectorAll(".refund-btn").forEach(button => {
            const orderId = button.dataset.orderId;
            let reviewed = false;

            document.querySelectorAll(`.review-btn[data-order-id="${orderId}"]`).forEach(reviewBtn => {
                const productId = reviewBtn.dataset.productId;
                const key = `${productId}_${orderId}`;

                if (reviewedProducts[key]) {
                    reviewed = true;
                    console.log(`🛑 Found reviewed item for refund block: ${key}`);
                }
            });

            if (reviewed) {
                button.textContent = "🛑 ขอคืนเงินไม่ได้ (รีวิวแล้ว)";
                button.classList.remove("btn-danger");
                button.classList.add("btn-secondary");
                button.disabled = true;
                button.style.pointerEvents = "none";
                button.style.cursor = "not-allowed";
            }
        });
    }
});
