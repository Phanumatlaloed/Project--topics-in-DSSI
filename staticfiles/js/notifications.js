function loadNotifications() {
    fetch("/api/notifications/")
        .then(response => response.json())
        .then(data => {
            const notificationList = document.getElementById("notification-list");
            notificationList.innerHTML = "";
            data.notifications.forEach(notification => {
                let li = document.createElement("li");
                li.innerHTML = notification.message;
                notificationList.appendChild(li);
            });
        });
}
setInterval(loadNotifications, 10000);
