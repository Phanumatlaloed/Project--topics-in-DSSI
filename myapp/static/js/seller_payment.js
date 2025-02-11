document.addEventListener("DOMContentLoaded", function () {
    function handleAction(action, orderId) {
        let url = `/seller/payments/${action}/${orderId}/`;

        fetch(url, {
            method: "GET",
            headers: { "X-Requested-With": "XMLHttpRequest" }
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                alert(`✅ ${data.message}`);
                document.querySelector(`tr[data-order-id="${orderId}"]`).remove(); // ลบแถวของออเดอร์ที่อนุมัติแล้ว
            } else {
                alert(`❌ ${data.message}`);
            }
        })
        .catch(error => console.error("Error:", error));
    }

    document.querySelectorAll(".approve").forEach(button => {
        button.addEventListener("click", function (event) {
            event.preventDefault();
            let orderId = this.getAttribute("data-order-id");
            if (confirm("คุณแน่ใจหรือไม่ว่าต้องการอนุมัติคำสั่งซื้อนี้?")) {
                handleAction("approve", orderId);
            }
        });
    });

    document.querySelectorAll(".reject").forEach(button => {
        button.addEventListener("click", function (event) {
            event.preventDefault();
            let orderId = this.getAttribute("data-order-id");
            if (confirm("คุณแน่ใจหรือไม่ว่าต้องการปฏิเสธคำสั่งซื้อนี้?")) {
                handleAction("reject", orderId);
            }
        });
    });
});
