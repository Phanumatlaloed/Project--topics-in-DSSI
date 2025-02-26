document.addEventListener("DOMContentLoaded", function () {
    const cancelButtons = document.querySelectorAll(".cancel-order-btn");

    cancelButtons.forEach(button => {
        button.addEventListener("click", function () {
            const orderId = this.dataset.orderId;

            // 🔄 เปลี่ยนจาก `prompt()` เป็นการนำทางไปที่หน้า `cancel_order.html`
            window.location.href = `/cancel-order/${orderId}/`;
        });
    });
});
