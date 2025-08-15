// group_follow.js - ไฟล์สำหรับจัดการการติดตามผู้ใช้ในหน้ากลุ่ม
document.addEventListener('DOMContentLoaded', function() {
    const followForms = document.querySelectorAll('.follow-form');
    
    followForms.forEach(form => {
        form.addEventListener('submit', function(e) {
            e.preventDefault();
            
            const userId = this.querySelector('.follow-btn').dataset.userId;
            const groupId = document.querySelector('.group-header-content').dataset.groupId || 
                            window.location.pathname.split('/')[2]; // ดึง group_id จาก URL ถ้าไม่มี dataset
            const csrfToken = this.querySelector('[name="csrfmiddlewaretoken"]').value;
            
            fetch(this.action, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'X-CSRFToken': csrfToken
                },
                body: new URLSearchParams({
                    'csrfmiddlewaretoken': csrfToken,
                    'group_id': groupId // ส่ง group_id ไปด้วยเพื่อให้ backend รู้ว่ามาจากหน้ากลุ่ม
                })
            })
            .then(response => {
                if (!response.ok) {
                    throw new Error('Network response was not ok');
                }
                return response.json();
            })
            .then(data => {
                if (data.success) {
                    // อัพเดททุกปุ่มที่เกี่ยวข้องกับผู้ใช้คนนี้ในหน้ากลุ่ม
                    const allButtons = document.querySelectorAll(`.follow-btn[data-user-id="${userId}"]`);
                    
                    allButtons.forEach(button => {
                        if (data.is_following) {
                            button.classList.remove('btn-outline-primary');
                            button.classList.add('btn-danger');
                            button.innerHTML = '<i class="fas fa-user-minus me-1"></i> ติดตามแล้ว';
                        } else {
                            button.classList.remove('btn-danger');
                            button.classList.add('btn-outline-primary');
                            button.innerHTML = '<i class="fas fa-user-plus me-1"></i> ติดตาม';
                        }
                    });
                    
                    // เก็บสถานะการติดตามลงใน localStorage สำหรับอ้างอิงหลังจาก refresh
                    updateFollowingStatus(userId, data.is_following, groupId);
                    
                    // แสดงข้อความแจ้งเตือน (optional)
                    showNotification(data.is_following ? 'เริ่มติดตามผู้ใช้แล้ว' : 'เลิกติดตามผู้ใช้แล้ว');
                } else {
                    console.error('Error:', data.error);
                    showNotification('เกิดข้อผิดพลาด โปรดลองอีกครั้ง', 'error');
                }
            })
            .catch(error => {
                console.error('Error:', error);
                showNotification('เกิดข้อผิดพลาด โปรดลองอีกครั้ง', 'error');
            });
        });
    });
    
    // ตรวจสอบและอัพเดทสถานะปุ่มติดตามหลังจากโหลดหน้า
    restoreFollowingStatus();
    
    // ฟังก์ชันสำหรับเก็บสถานะการติดตามลงใน localStorage
    function updateFollowingStatus(userId, isFollowing, groupId) {
        try {
            // ดึงข้อมูลการติดตามปัจจุบัน
            let followingData = JSON.parse(localStorage.getItem('groupFollowingStatus')) || {};
            
            // ถ้ายังไม่มีข้อมูลของกลุ่มนี้ ให้สร้างใหม่
            if (!followingData[groupId]) {
                followingData[groupId] = {};
            }
            
            // อัพเดทสถานะการติดตามของผู้ใช้นี้
            followingData[groupId][userId] = isFollowing;
            
            // บันทึกกลับลง localStorage
            localStorage.setItem('groupFollowingStatus', JSON.stringify(followingData));
        } catch (e) {
            console.error('Error updating following status in localStorage:', e);
        }
    }
    
    // ฟังก์ชันสำหรับดึงสถานะการติดตามจาก localStorage และอัพเดทปุ่มหลังจากโหลดหน้า
    function restoreFollowingStatus() {
        try {
            const groupId = document.querySelector('.group-header-content').dataset.groupId || 
                           window.location.pathname.split('/')[2]; // ดึง group_id จาก URL
            
            // ดึงข้อมูลการติดตามที่บันทึกไว้
            let followingData = JSON.parse(localStorage.getItem('groupFollowingStatus')) || {};
            
            // ถ้าไม่มีข้อมูลของกลุ่มนี้ ให้ออกจากฟังก์ชัน
            if (!followingData[groupId]) return;
            
            // วนลูปอัพเดทปุ่มตามสถานะที่บันทึกไว้
            Object.entries(followingData[groupId]).forEach(([userId, isFollowing]) => {
                const buttons = document.querySelectorAll(`.follow-btn[data-user-id="${userId}"]`);
                
                buttons.forEach(button => {
                    if (isFollowing) {
                        button.classList.remove('btn-outline-primary');
                        button.classList.add('btn-danger');
                        button.innerHTML = '<i class="fas fa-user-minus me-1"></i> ติดตามแล้ว';
                    } else {
                        button.classList.remove('btn-danger');
                        button.classList.add('btn-outline-primary');
                        button.innerHTML = '<i class="fas fa-user-plus me-1"></i> ติดตาม';
                    }
                });
            });
        } catch (e) {
            console.error('Error restoring following status from localStorage:', e);
        }
    }
    
    // ฟังก์ชันแสดงข้อความแจ้งเตือน
    function showNotification(message, type = 'success') {
        // สร้างองค์ประกอบสำหรับแจ้งเตือน
        const notification = document.createElement('div');
        notification.className = `notification ${type}`;
        notification.innerHTML = `<i class="fas ${type === 'success' ? 'fa-check-circle' : 'fa-exclamation-circle'}"></i> ${message}`;
        
        // เพิ่มเข้าไปในหน้าเว็บ
        document.body.appendChild(notification);
        
        // แสดง notification
        setTimeout(() => {
            notification.classList.add('show');
        }, 10);
        
        // ซ่อน notification หลังจาก 3 วินาที
        setTimeout(() => {
            notification.classList.remove('show');
            setTimeout(() => {
                notification.remove();
            }, 300);
        }, 3000);
    }
});

// เพิ่ม CSS สำหรับแจ้งเตือน
document.addEventListener('DOMContentLoaded', function() {
    // สร้าง <style> element
    const style = document.createElement('style');
    style.textContent = `
        .notification {
            position: fixed;
            top: 20px;
            right: 20px;
            padding: 12px 20px;
            background-color: #ffffff;
            color: #333;
            border-radius: 5px;
            box-shadow: 0 4px 10px rgba(0, 0, 0, 0.1);
            z-index: 9999;
            opacity: 0;
            transform: translateY(-20px);
            transition: opacity 0.3s, transform 0.3s;
            display: flex;
            align-items: center;
            gap: 10px;
            font-family: 'Prompt', sans-serif;
        }
        
        .notification.show {
            opacity: 1;
            transform: translateY(0);
        }
        
        .notification.success {
            border-left: 4px solid #4CAF50;
        }
        
        .notification.error {
            border-left: 4px solid #F44336;
        }
        
        .notification i {
            font-size: 18px;
        }
        
        .notification.success i {
            color: #4CAF50;
        }
        
        .notification.error i {
            color: #F44336;
        }
    `;
    
    // เพิ่ม style เข้าไปใน <head>
    document.head.appendChild(style);
});