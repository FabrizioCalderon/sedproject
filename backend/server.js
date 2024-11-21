const http = require('http');
const fs = require('fs');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const multer = require('multer');

const PORT = 3000;
const SECRET_KEY = "hola";
let sessions = {}; // Manejo básico de sesiones
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir, { recursive: true });
}

// Configuración de almacenamiento con Multer
const storage = multer.diskStorage({
    destination: function(req, file, cb) {
        const uploadsDir = path.join(__dirname, 'uploads');
        if (!fs.existsSync(uploadsDir)){
            fs.mkdirSync(uploadsDir, { recursive: true });
        }
        cb(null, uploadsDir);
    },
    filename: function(req, file, cb) {
        // Generar un nombre de archivo único sin espacios
        const timestamp = Date.now();
        const originalName = file.originalname.replace(/\s+/g, '-');
        const uniqueName = `${timestamp}-${originalName}`;
        cb(null, uniqueName);
    }
});

const upload = multer({ storage: storage });

// Configurar los tipos de archivos permitidos
const fileFilter = (req, file, cb) => {
    // Acepta imágenes, PDFs y documentos comunes
    const allowedTypes = /jpeg|jpg|png|gif|pdf|doc|docx|txt/;
    const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = allowedTypes.test(file.mimetype);

    if (extname && mimetype) {
        cb(null, true);
    } else {
        cb(new Error('Solo se permiten archivos de imagen, PDF y documentos!'));
    }
};

// Configurar multer con las opciones


// Inicializar la base de datos SQLite
const db = new sqlite3.Database('database.db', (err) => {
    if (err) {
        console.error(err.message);
    } else {
        console.log('Connected to the SQLite database.');
        db.run(`CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            role TEXT
        );`);
        db.run(`CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT,
            content TEXT,
            author_id INTEGER,
            file_path TEXT,
            FOREIGN KEY(author_id) REFERENCES users(id)
        );`);
        db.run(`CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            post_id INTEGER,
            username TEXT,
            content TEXT,
            FOREIGN KEY(post_id) REFERENCES posts(id)
        );`);
    }
});

// Función para servir archivos estáticos
function serveStaticFile(res, filepath, contentType) {
    fs.readFile(filepath, (err, data) => {
        if (err) {
            res.writeHead(404, { 'Content-Type': 'text/plain' });
            res.end('404 Not Found');
        } else {
            res.writeHead(200, { 'Content-Type': contentType });
            res.end(data);
        }
    });
}

// Función para determinar el tipo de contenido
function getContentType(filePath) {
    const ext = path.extname(filePath).toLowerCase();
    const mimeTypes = {
        // Imágenes
        '.png': 'image/png',
        '.jpg': 'image/jpeg',
        '.jpeg': 'image/jpeg',
        '.gif': 'image/gif',
        '.bmp': 'image/bmp',
        '.webp': 'image/webp',
        '.svg': 'image/svg+xml',
        
        // Documentos
        '.pdf': 'application/pdf',
        '.doc': 'application/msword',
        '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        '.xls': 'application/vnd.ms-excel',
        '.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        '.ppt': 'application/vnd.ms-powerpoint',
        '.pptx': 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
        
        // Texto
        '.txt': 'text/plain',
        '.csv': 'text/csv',
        '.md': 'text/markdown',
        
        // Web
        '.html': 'text/html',
        '.htm': 'text/html',
        '.css': 'text/css',
        '.js': 'application/javascript',
        '.json': 'application/json',
        
        // Comprimidos
        '.zip': 'application/zip',
        '.rar': 'application/x-rar-compressed',
        '.7z': 'application/x-7z-compressed',
        '.tar': 'application/x-tar',
        '.gz': 'application/gzip'
    };

    return mimeTypes[ext] || 'application/octet-stream';
}

// Crear el servidor HTTP
const server = http.createServer((req, res) => {
    console.log(`Request received: ${req.method} ${req.url}`);

    if (req.method === 'GET') {
        const urlPath = req.url;
        if (req.url === '/' || req.url === '/index.html') {
            serveStaticFile(res, path.join(__dirname, '../frontend/templates/index.html'), 'text/html');
        } else if (req.url === '/login.html') {
            serveStaticFile(res, path.join(__dirname, '../frontend/templates/login.html'), 'text/html');
        } else if (req.url === '/register.html') {
            serveStaticFile(res, path.join(__dirname, '../frontend/templates/register.html'), 'text/html');
        } else if (req.url === '/create_post.html') {
            serveStaticFile(res, path.join(__dirname, '../frontend/templates/create_post.html'), 'text/html');
        }else if (req.url === '/superadmin_dashboard.html') {
            serveStaticFile(res, path.join(__dirname, '../frontend/templates/superadmin_dashboard.html'), 'text/html');
        }else if (req.url === '/admin_dashboard.html'){
            serveStaticFile(res, path.join(__dirname, '../frontend/templates/admin_dashboard.html'), 'text/html');
        }else if (req.url === '/system_settings.html'){
            serveStaticFile(res, path.join(__dirname, '../frontend/templates/system_settings.html'), 'text/html');
        }else if (req.url.startsWith('/post.html')) {
            const filePath = path.join(__dirname, '../frontend/templates/post.html');
            serveStaticFile(res, filePath, 'text/html');
        }else if (req.url === '/manage_roles.html'){
            serveStaticFile(res, path.join(__dirname, '../frontend/templates/manage_roles.html'), 'text/html');
        }else if (req.url.startsWith('/css/')) {
            serveStaticFile(res, path.join(__dirname, '../frontend', req.url), 'text/css');
        } else if (req.url.startsWith('/js/')) {
            serveStaticFile(res, path.join(__dirname, '../frontend', req.url), 'application/javascript');
        }// En el servidor, modifica la parte que maneja las rutas /uploads/
else if (req.url.startsWith('/uploads/')) {
    try {
        // Decodificar la URL
        const requestedPath = decodeURIComponent(req.url.split('?')[0]); // Removemos los query params
        const fileName = path.basename(requestedPath);
        
        // Construir la ruta completa al archivo
        const filePath = path.join(__dirname, 'uploads', fileName);
        
        console.log('Requested file:', fileName);
        console.log('Full path:', filePath);
        
        // Verificar que el archivo existe
        if (!fs.existsSync(filePath)) {
            res.writeHead(404, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'File not found' }));
            return;
        }

        // Leer estadísticas del archivo
        const stat = fs.statSync(filePath);
        const contentType = getContentType(filePath);

        // Configurar headers para la descarga
        res.writeHead(200, {
            'Content-Type': contentType,
            'Content-Length': stat.size,
            'Content-Disposition': `attachment; filename="${fileName}"`,
            'Cache-Control': 'no-cache'
        });

        // Enviar el archivo directamente
        fs.createReadStream(filePath).pipe(res);

    } catch (error) {
        console.error('Error serving file:', error);
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Internal server error' }));
    }
}else if (req.url === '/posts') {
            db.all(`
                SELECT 
                    posts.id, 
                    posts.title, 
                    posts.content, 
                    posts.file_path,
                    CASE 
                        WHEN posts.author_id IS NULL THEN 'Unknown'
                        WHEN typeof(posts.author_id) = 'text' THEN posts.author_id
                        ELSE COALESCE((SELECT username FROM users WHERE id = posts.author_id), posts.author_id)
                    END as author
                FROM posts
            `, [], (err, rows) => {
                if (err) {
                    console.error('Database error:', err);
                    res.writeHead(500, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ error: 'Failed to fetch posts' }));
                } else {
                    const formattedPosts = rows.map(post => ({
                        ...post,
                        file_path: post.file_path ? '/uploads/' + post.file_path.split('\\').pop() : null
                    }));
                    res.writeHead(200, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify(formattedPosts));
                }
            });
        }else if (req.url === '/api/session') {
            const cookies = req.headers.cookie || '';
            const sessionId = cookies.split('=')[1];
        
            if (!sessionId || !sessions[sessionId]) {
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ loggedIn: false }));
                return;
            }
        
            const session = sessions[sessionId];
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ loggedIn: true, role: session.role }));
        } else if (req.url === '/users') {
            db.all('SELECT * FROM users', [], (err, rows) => {
                if (err) {
                    res.writeHead(500, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ error: 'Failed to fetch users' }));
                } else {
                    res.writeHead(200, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify(rows));
                }
            });
        }else if (req.method === 'GET' && req.url === '/settings') {
            db.all(`SELECT * FROM settings`, [], (err, rows) => {
                if (err) {
                    res.writeHead(500, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ error: 'Failed to fetch settings' }));
                } else {
                    res.writeHead(200, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify(rows));
                }
            });
        }else if (req.url.startsWith('/posts/')) {
            const postId = urlPath.split('/')[2];
            if (!postId) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: 'Invalid post ID' }));
                return;
            }

            db.get(`
                SELECT posts.id, posts.title, posts.content, posts.file_path, users.username AS author
                FROM posts
                JOIN users ON posts.author_id = users.id
                WHERE posts.id = ?
            `, [postId], (err, post) => {
                if (err || !post) {
                    res.writeHead(404, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ error: 'Post not found' }));
                    return;
                }

                db.all(`SELECT * FROM comments WHERE post_id = ?`, [postId], (err, comments) => {
                    if (err) {
                        res.writeHead(500, { 'Content-Type': 'application/json' });
                        res.end(JSON.stringify({ error: 'Failed to fetch comments' }));
                    } else {
                        res.writeHead(200, { 'Content-Type': 'application/json' });
                        res.end(JSON.stringify({ post, comments }));
                    }
                });
            });
        }
        else if (req.method === 'GET' && req.url.startsWith('/comments')) {
            const urlParams = new URLSearchParams(req.url.split('?')[1]);
            const postId = urlParams.get('postId');
            
            if (!postId) {
                res.writeHead(400, { 'Content-Type': 'text/plain' });
                res.end('Invalid post ID');
                return;
            }
        
            db.all(`SELECT * FROM comments WHERE post_id = ?`, [postId], (err, rows) => {
                if (err) {
                    res.writeHead(500, { 'Content-Type': 'text/plain' });
                    res.end('Error retrieving comments');
                } else {
                    res.writeHead(200, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify(rows));
                }
            });
        }
        
        
        
        
    } else if (req.method === 'POST') {
        if (req.url === '/register') {
            let body = '';
            req.on('data', chunk => { body += chunk; });
            req.on('end', () => {
                // Cambiar el nombre del campo para aceptar 'secret-key'
                const { username, password, role, secretKey = SECRET_KEY } = JSON.parse(body);

        
                if ((role === 'admin' || role === 'superadmin') && secretKey !== SECRET_KEY) {
                    res.writeHead(400, { 'Content-Type': 'text/plain' });
                    res.end('Invalid secret key.');
                    return;
                }
        
                const hashedPassword = bcrypt.hashSync(password, 10);
                db.run(`INSERT INTO users (username, password, role) VALUES (?, ?, ?)`, [username, hashedPassword, role], function (err) {
                    if (err) {
                        res.writeHead(400, { 'Content-Type': 'text/plain' });
                        res.end('User already exists or invalid input.');
                    } else {
                        res.writeHead(201, { 'Content-Type': 'text/plain' });
                        res.end('User registered successfully.');
                    }
                });
            });
        }else if (req.url === '/login') {
            let body = '';
            req.on('data', chunk => { body += chunk; });
            req.on('end', () => {
                const { username, password } = JSON.parse(body);
                db.get(`SELECT * FROM users WHERE username = ?`, [username], (err, user) => {
                    if (err || !user || !bcrypt.compareSync(password, user.password)) {
                        res.writeHead(401, { 'Content-Type': 'text/plain' });
                        res.end('Invalid credentials.');
                    } else {
                        const sessionId = crypto.randomBytes(16).toString('hex');
                        sessions[sessionId] = { username: user.username, role: user.role };
                        res.writeHead(200, {
                            'Content-Type': 'text/plain',
                            'Set-Cookie': `sessionId=${sessionId}; HttpOnly`
                        });
                        res.end('Login successful.');
                    }
                });
            });
        } else if (req.method === 'POST') {
            if (req.url === '/posts') {
                upload.single('file')(req, res, (err) => {
                    if (err) {
                        res.writeHead(400, { 'Content-Type': 'text/plain' });
                        res.end('Failed to upload file');
                        return;
                    }
    
                    const { title, content } = req.body || {};
                    const cookies = req.headers.cookie || '';
                    const sessionId = cookies.split('=')[1];
                    const session = sessions[sessionId];
    
                    if (!session) {
                        res.writeHead(401, { 'Content-Type': 'text/plain' });
                        res.end('Unauthorized');
                        return;
                    }
    
                    const author_id = session.username; // Cambia según tu implementación
                    const filePath = req.file ? req.file.path : null;
    
                    db.run(`
                        INSERT INTO posts (title, content, author_id, file_path)
                        VALUES (?, ?, ?, ?)
                    `, [title, content, author_id, filePath], function (err) {
                        if (err) {
                            res.writeHead(500, { 'Content-Type': 'text/plain' });
                            res.end('Failed to create post');
                        } else {
                            res.writeHead(201, { 'Content-Type': 'application/json' });
                            res.end(JSON.stringify({ success: true, filePath: filePath ? filePath.replace(/\\/g, '/') : null }));
                        }
                    });
                });
            }else if (req.method === 'POST' && req.url === '/comments') {
            let body = '';
            req.on('data', (chunk) => {
                body += chunk;
            });
        
            req.on('end', () => {
                try {
                    const { postId, content } = JSON.parse(body);
                    console.log("Payload recibido:", { postId, content });
            
                    // Validate session
                    const cookies = req.headers.cookie || '';
                    const sessionId = cookies.split('=')[1];
            
                    if (!sessionId || !sessions[sessionId]) {
                        res.writeHead(401, { 'Content-Type': 'application/json' });
                        res.end(JSON.stringify({ error: 'Unauthorized' }));
                        return;
                    }
            
                    // Retrieve the session object
                    const session = sessions[sessionId];
            
                    // Validate postId and content
                    const postIdNum = parseInt(postId, 10);
                    if (!postIdNum || !content) {
                        console.log("postId o content inválido");
                        res.writeHead(400, { 'Content-Type': 'application/json' });
                        res.end(JSON.stringify({ error: 'Invalid post ID or content' }));
                        return;
                    }
            
                    // Validate postId in the database
                    db.get(`SELECT id FROM posts WHERE id = ?`, [postIdNum], (err, row) => {
                        if (err) {
                            console.error("Error en la consulta:", err);
                            res.writeHead(500, { 'Content-Type': 'application/json' });
                            res.end(JSON.stringify({ error: 'Database error' }));
                            return;
                        }
            
                        if (!row) {
                            console.log("Post ID no encontrado en la base de datos:", postIdNum);
                            res.writeHead(400, { 'Content-Type': 'application/json' });
                            res.end(JSON.stringify({ error: 'Invalid post ID' }));
                            return;
                        }
            
                        // Insert comment if postId is valid
                        db.run(
                            `INSERT INTO comments (post_id, username, content) VALUES (?, ?, ?)`,
                            [postIdNum, session.username, content],
                            function (err) {
                                if (err) {
                                    console.error("Error al agregar el comentario:", err);
                                    res.writeHead(500, { 'Content-Type': 'application/json' });
                                    res.end(JSON.stringify({ error: 'Failed to add comment' }));
                                } else {
                                    console.log("Comentario agregado con éxito");
                                    res.writeHead(201, { 'Content-Type': 'application/json' });
                                    res.end(JSON.stringify({ success: true }));
                                }
                            }
                        );
                    });
                } catch (error) {
                    console.error("Error al procesar la solicitud:", error);
                    res.writeHead(400, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ error: 'Invalid JSON format' }));
                }
            });
        }
        }else if (req.url === '/logout') {
            const cookies = req.headers.cookie || '';
            const sessionId = cookies.split('=')[1];
        
            if (sessionId && sessions[sessionId]) {
                delete sessions[sessionId]; // Eliminar la sesión del servidor
            }
        
            res.writeHead(200, { 'Content-Type': 'text/plain', 'Set-Cookie': 'sessionId=; HttpOnly; Max-Age=0' });
            res.end('Logged out successfully.');
        }else if (req.method === 'POST' && req.url === '/settings') {
            let body = '';
            req.on('data', chunk => { body += chunk; });
            req.on('end', () => {
                const { key, value } = JSON.parse(body);
                db.run(`INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)`, [key, value], (err) => {
                    if (err) {
                        res.writeHead(500, { 'Content-Type': 'application/json' });
                        res.end(JSON.stringify({ error: 'Failed to update settings' }));
                    } else {
                        res.writeHead(200, { 'Content-Type': 'application/json' });
                        res.end(JSON.stringify({ success: true }));
                    }
                });
            });
        }else if (req.method === 'POST' && req.url === '/update-role') {
            let body = '';
            req.on('data', chunk => { body += chunk; });
            req.on('end', () => {
                const { userId, newRole } = JSON.parse(body);
                db.run(`UPDATE users SET role = ? WHERE id = ?`, [newRole, userId], (err) => {
                    if (err) {
                        res.writeHead(500, { 'Content-Type': 'application/json' });
                        res.end(JSON.stringify({ error: 'Failed to update role' }));
                    } else {
                        res.writeHead(200, { 'Content-Type': 'application/json' });
                        res.end(JSON.stringify({ success: true }));
                    }
                });
            });
        }else {
            res.writeHead(404, { 'Content-Type': 'text/plain' });
            res.end('404 Not Found');
        }
    } else {
        res.writeHead(405, { 'Content-Type': 'text/plain' });
        res.end('Method Not Allowed');
    }
});


// Iniciar el servidor
server.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}/`);
});
