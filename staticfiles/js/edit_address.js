document.addEventListener("DOMContentLoaded", function () {
    console.log("✅ edit_address.js Loaded!");

    // ค้นหาปุ่ม "แก้ไขที่อยู่" ทั้งหมด
    document.querySelectorAll(".edit-address-btn").forEach(button => {
        button.addEventListener("click", function () {
            let orderId = this.dataset.orderId;
            let address = this.dataset.address || "";
            let city = this.dataset.city || "";
            let postalCode = this.dataset.postalCode || "";
            let phone = this.dataset.phone || "";

            // เติมค่าลงใน Modal
            document.getElementById("order-id").value = orderId;
            document.getElementById("edit-address").value = address;
            document.getElementById("edit-city").value = city;
            document.getElementById("edit-postal-code").value = postalCode;
            document.getElementById("edit-phone").value = phone;

            // แสดง Modal
            let modal = new bootstrap.Modal(document.getElementById("editAddressModal"));
            modal.show();
        });
    });

    // ปุ่มบันทึกที่อยู่
    document.getElementById("save-address-btn").addEventListener("click", function () {
        let orderId = document.getElementById("order-id").value;
        let newAddress = document.getElementById("edit-address").value.trim();
        let newCity = document.getElementById("edit-city").value.trim();
        let newPostal = document.getElementById("edit-postal-code").value.trim();
        let newPhone = document.getElementById("edit-phone").value.trim();

        if (!newAddress || !newCity || !newPostal || !newPhone) {
            alert("❌ กรุณากรอกข้อมูลให้ครบถ้วน");
            return;
        }

        // ดึง CSRF Token
        let csrfToken = document.querySelector("meta[name='csrf-token']").content;

        fetch(`/update-address/${orderId}/`, {
            method: "POST",
            headers: {
                "Content-Type": "application/x-www-form-urlencoded",
                "X-CSRFToken": csrfToken
            },
            body: `address=${encodeURIComponent(newAddress)}&city=${encodeURIComponent(newCity)}&postal_code=${encodeURIComponent(newPostal)}&phone_number=${encodeURIComponent(newPhone)}`
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                alert("✅ ที่อยู่ถูกอัปเดตเรียบร้อย!");
                
                // อัปเดตค่าบนหน้าเว็บโดยไม่ต้องรีเฟรช
                document.getElementById(`order-address-${orderId}`).innerText = newAddress;
                document.getElementById(`order-city-${orderId}`).innerText = newCity;
                document.getElementById(`order-postal-${orderId}`).innerText = newPostal;
                document.getElementById(`order-phone-${orderId}`).innerText = newPhone;

                let modal = bootstrap.Modal.getInstance(document.getElementById("editAddressModal"));
                modal.hide();
            } else {
                alert("❌ อัปเดตไม่สำเร็จ: " + data.error);
            }
        })
        .catch(error => console.error("❌ Error:", error));
    });
});
