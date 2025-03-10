document.addEventListener("DOMContentLoaded", function () {
    console.log("✅ JavaScript Loaded: review.js");

    // ✅ โหลดข้อมูลสินค้ารีวิวจาก LocalStorage (ถ้ามี)
    let reviewedProducts = {};
    try {
        let storedReviews = localStorage.getItem("reviewedProducts");
        if (storedReviews) {
            reviewedProducts = JSON.parse(storedReviews);
        } else {
            localStorage.setItem("reviewedProducts", JSON.stringify({}));
        }
    } catch (error) {
        console.error("❌ JSON Parsing Error:", error);
        localStorage.setItem("reviewedProducts", JSON.stringify({}));
    }

    console.log("🔍 DEBUG: Loaded Reviewed Products ->", reviewedProducts);

    // ✅ ตรวจสอบปุ่มรีวิวทุกปุ่ม และกำหนดสถานะ
    document.querySelectorAll(".review-btn").forEach(button => {
        let orderId = button.dataset.orderId;
        let productId = button.dataset.productId;
        let key = `${productId}_${orderId}`;

        // ✅ ถ้าถูกรีวิวแล้ว ให้ปิดการใช้งานปุ่มรีวิว
        if (reviewedProducts[key]) {
            button.textContent = "✅ รีวิวแล้ว";
            button.classList.remove("btn-primary");
            button.classList.add("btn-secondary");
            button.disabled = true;
        }

        // ✅ เมื่อคลิกปุ่ม ให้บันทึกสถานะรีวิวลง LocalStorage และเปลี่ยน UI ทันที
        button.addEventListener("click", function () {
            reviewedProducts[key] = true;
            localStorage.setItem("reviewedProducts", JSON.stringify(reviewedProducts));

            button.textContent = "✅ รีวิวแล้ว";
            button.classList.remove("btn-primary");
            button.classList.add("btn-secondary");
            button.disabled = true;

            updateRefundButtons();
        });
    });

    // ✅ ฟังก์ชันอัปเดตปุ่มขอคืนเงินให้ปิดการใช้งานหากมีสินค้าถูกรีวิวแล้ว
    function updateRefundButtons() {
        document.querySelectorAll(".refund-btn").forEach(button => {
            let orderId = button.dataset.orderId;
            let reviewed = false;

            // ✅ เช็คทุกสินค้าภายในออเดอร์ ถ้ามีสินค้าถูกรีวิวแล้ว ให้ปิดปุ่ม
            document.querySelectorAll(`.review-btn[data-order-id="${orderId}"]`).forEach(reviewBtn => {
                let productId = reviewBtn.dataset.productId;
                let key = `${productId}_${orderId}`;

                if (reviewedProducts[key]) {
                    reviewed = true;
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

    // ✅ เรียกใช้งานตอนโหลดหน้าเว็บ
    updateRefundButtons();
});
