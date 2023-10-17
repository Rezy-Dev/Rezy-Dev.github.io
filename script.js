document.addEventListener('DOMContentLoaded', function () {
    const loadingContainer = document.querySelector('.loading-container');
    const content = document.querySelector('.content');
    const hackerTitle = document.querySelector('.hacker-title');
    
    
    setTimeout(function () {
        loadingContainer.style.display = 'none';
        content.style.display = 'block';
    }, 3000);
});
