const API_URL = "http://localhost:3000";
const SECRET_KEY = "hola";

// Load header dynamically
function loadHeader() {
    const header = document.getElementById('header');
    if (!header) {
        console.error("Header element not found.");
        return;
    }
    fetch('/api/session')
        .then(response => response.json())
        .then(session => {
            if (session.loggedIn) {
                let userOptions = `
                    <a href="index.html">Home</a>
                    <a href="create_post.html">Create Post</a>
                    <a href="#" id="logout-button">Logout</a>
                `;
                if (session.role === 'admin') {
                    userOptions += `<a href="admin_dashboard.html">Admin Dashboard</a>`;
                } else if (session.role === 'superadmin') {
                    userOptions += `<a href="superadmin_dashboard.html">Superadmin Dashboard</a>`;
                }
                header.innerHTML = userOptions;
                document.getElementById('logout-button')?.addEventListener('click', logoutUser);
            } else {
                header.innerHTML = `
                    <a href="index.html">Home</a>
                    <a href="login.html">Login</a>
                    <a href="register.html">Register</a>
                `;
            }
        })
        .catch(error => {
            console.error('Error fetching session data:', error);
            header.innerHTML = `
                <a href="index.html">Home</a>
                <a href="login.html">Login</a>
                <a href="register.html">Register</a>
            `;
        });
}


async function loadPost(postId) {
    try {
        // Cargar el post
        const postResponse = await fetch(`${API_URL}/posts/${postId}`);
        if (!postResponse.ok) {
            throw new Error('Failed to load post');
        }
        const post = await postResponse.json();
        document.getElementById('post-title').textContent = post.title;
        document.getElementById('post-content').textContent = post.content;
        document.getElementById('post-file').textContent = post.file || ''; // Si hay archivo

        // Cargar los comentarios
        const commentsResponse = await fetch(`${API_URL}/comments?postId=${postId}`);
        if (!commentsResponse.ok) {
            throw new Error('Failed to load comments');
        }
        const comments = await commentsResponse.json();
        const commentsContainer = document.getElementById('comments-container');
        commentsContainer.innerHTML = ''; // Limpiar comentarios previos
        comments.forEach(comment => {
            const commentElement = document.createElement('div');
            commentElement.classList.add('comment');
            commentElement.innerHTML = `
                <p><strong>${comment.username}</strong>: ${comment.content}</p>
            `;
            commentsContainer.appendChild(commentElement);
        });
    } catch (error) {
        console.error('Error loading post and comments:', error);
    }
}







// Load posts
function loadPosts() {
    fetch(`${API_URL}/posts`)
        .then(response => response.json())
        .then(posts => {
            const container = document.getElementById('posts-container');
            if (!container) {
                console.error("Posts container not found.");
                return;
            }
            if (posts.length === 0) {
                container.innerHTML = '<p>No posts available.</p>';
                return;
            }
            
            container.innerHTML = posts.map(post => {
                let fileAttachment = '';
                if (post.file_path) {
                    // Extraer el nombre del archivo
                    const fileName = post.file_path.split('\\').pop().split('/').pop();
                    const fileUrl = `/uploads/${encodeURIComponent(fileName)}`;
                    
                    // Determinar si es una imagen
                    const imageExtensions = ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp'];
                    const isImage = imageExtensions.some(ext => 
                        fileName.toLowerCase().endsWith(ext)
                    );
                    
                    if (isImage) {
                        fileAttachment = `
                            <div class="file-attachment">
                                <img src="${fileUrl}" alt="${fileName}" style="max-width: 200px; max-height: 200px;">
                                <br>
                                <button onclick="downloadFile('${fileUrl}', '${fileName}')" class="download-link">
                                    Download image
                                </button>
                            </div>`;
                    } else {
                        fileAttachment = `
                            <div class="file-attachment">
                                <p><strong>Attached file:</strong> 
                                    <button onclick="downloadFile('${fileUrl}', '${fileName}')" class="download-link">
                                        Download ${fileName}
                                    </button>
                                </p>
                            </div>`;
                    }
                }

                return `
                    <div class="post">
                        <h2><a href="/post.html?id=${post.id}">${post.title}</a></h2>
                        <p class="post-content">${post.content.substring(0, 100)}${post.content.length > 100 ? '...' : ''}</p>
                        <p class="post-author"><strong>Author:</strong> ${post.author}</p>
                        ${fileAttachment}
                    </div>
                `;
            }).join('');
            
            // Agregar estilos para los botones de descarga
            const style = document.createElement('style');
            style.textContent = `
                .download-link {
                    display: inline-block;
                    padding: 5px 10px;
                    background-color: #007bff;
                    color: white;
                    border: none;
                    border-radius: 4px;
                    cursor: pointer;
                    font-size: 14px;
                    margin-top: 5px;
                }
                .download-link:hover {
                    background-color: #0056b3;
                }
                .file-attachment {
                    margin: 10px 0;
                    padding: 10px;
                    border: 1px solid #ddd;
                    border-radius: 4px;
                }
            `;
            document.head.appendChild(style);
        })
        .catch(error => {
            console.error('Error loading posts:', error);
            const container = document.getElementById('posts-container');
            if (container) {
                container.innerHTML = '<p>Error loading posts. Please try again later.</p>';
            }
        });
}

// Función para manejar la descarga de archivos
function downloadFile(url, fileName) {
    // Crear un elemento <a> temporal
    const link = document.createElement('a');
    link.href = url;
    link.download = fileName; // Establecer el nombre del archivo
    link.style.display = 'none';
    
    // Agregar el enlace al documento
    document.body.appendChild(link);
    
    // Simular clic en el enlace
    link.click();
    
    // Limpiar
    document.body.removeChild(link);
}




// Handle registration
document.getElementById('register-form')?.addEventListener('submit', async (event) => {
    event.preventDefault();
    const formData = new FormData(event.target);
    const data = Object.fromEntries(formData.entries());

    if (data['secret-key']) {
        data.secretKey = data['secret-key'];
        delete data['secret-key'];
    }

    if ((data.role === 'admin' || data.role === 'superadmin') && !data.secretKey) {
        alert('Secret key is required for Admin and Superadmin roles.');
        return;
    }

    try {
        const response = await fetch(`${API_URL}/register`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data),
        });
        const message = await response.text();
        alert(message);
        if (response.ok) window.location.href = 'login.html';
    } catch (error) {
        console.error('Error registering user:', error);
    }
});

// Handle login
document.getElementById('login-form')?.addEventListener('submit', async (event) => {
    event.preventDefault();
    const formData = new FormData(event.target);
    const data = Object.fromEntries(formData.entries());
    if (!data.username || !data.password) {
        alert('Username and password are required.');
        return;
    }
    try {
        const response = await fetch(`${API_URL}/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data),
        });
        const message = await response.text();
        alert(message);
        if (response.ok) {
            loadHeader(); // Update header immediately
            window.location.href = 'index.html';
        }
    } catch (error) {
        console.error('Error logging in:', error);
    }
});

// Handle logout
async function logoutUser() {
    try {
        const response = await fetch(`${API_URL}/logout`, { method: 'POST' });
        if (response.ok) {
            alert('Logged out successfully.');
            window.location.href = 'index.html';
        } else {
            alert('Failed to log out.');
        }
    } catch (error) {
        console.error('Error logging out:', error);
    }
}

// Handle post creation
document.getElementById('post-form')?.addEventListener('submit', async (event) => {
    event.preventDefault();

    const formData = new FormData(event.target);

    try {
        const response = await fetch(`${API_URL}/posts`, {
            method: 'POST',
            body: formData,
        });

        const result = await response.json();
        if (response.ok) {
            alert('Post created successfully!');
            console.log('File saved at:', result.filePath);
            window.location.href = 'index.html';
        } else {
            alert('Failed to create post.');
        }
    } catch (error) {
        console.error('Error creating post:', error);
    }
});

// Show or hide secret key field dynamically
document.getElementById('role')?.addEventListener('change', (event) => {
    const secretKeyField = document.getElementById('secret-key-field');
    if (secretKeyField) {
        secretKeyField.style.display = (event.target.value === 'admin' || event.target.value === 'superadmin') ? 'block' : 'none';
    }
});
