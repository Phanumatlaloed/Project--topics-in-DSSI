document.addEventListener("DOMContentLoaded", function () {
    document.body.addEventListener("click", function (event) {
        if (event.target.classList.contains("cancel-order-btn")) {
            const orderId = event.target.dataset.orderId;
            
            if (confirm(`คุณต้องการยกเลิกออเดอร์ #${orderId} ใช่หรือไม่?`)) {
                window.location.href = `/cancel-order/${orderId}/`;
            }
        }
    });
});
