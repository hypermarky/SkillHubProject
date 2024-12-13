document.addEventListener("DOMContentLoaded", () => {
    const chatTabs = document.querySelectorAll(".chat-tab");
    const chatContent = document.getElementById("chatContent");
    const messageButtons = document.querySelectorAll(".message-btn");

    chatTabs.forEach(tab => {
        tab.addEventListener("click", () => {
            const userId = tab.dataset.chatUserId;
            loadChat(userId);
        });
    });

    messageButtons.forEach(button => {
        button.addEventListener("click", () => {
            const userId = button.dataset.userId;
            loadChat(userId);
        });
    });

    function loadChat(userId) {
        fetch(`/messages/${userId}`)
            .then(response => {
                if (!response.ok) {
                    throw new Error("Network response was not ok");
                }
                return response.text();
            })
            .then(html => {
                chatContent.innerHTML = html;
                document.querySelector(".chat-box").classList.add("chat-box-open");
            })
            .catch(error => {
                console.error("Error fetching chat:", error);
                chatContent.innerHTML = `<p class="text-danger">Unable to load chat. Please try again later.</p>`;
            });
    }
});
