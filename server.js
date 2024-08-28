const sql = require('mssql');
const jwt = require('jsonwebtoken');
const express = require('express');
const cors = require('cors'); // เพิ่มการใช้งาน CORS
const bcrypt = require('bcryptjs'); // Import bcrypt


const app = express();

app.use(express.json());
app.use(cors());




const secretKey = '64011212016';

// การตั้งค่าการเชื่อมต่อฐานข้อมูล
const dbConfig = {
    user: 'APD66_64011212016',
    password: 'ZX0LE35U',
    server: '202.28.34.203\\SQLEXPRESS',
    // server: 'mssql',
    database: 'APD66_64011212016',
    options: {
        encrypt: true,
        enableArithAbort: true,
        trustServerCertificate: true,
        connectTimeout: 60000,
        requestTimeout: 60000
        
    }
};

// เชื่อมต่อกับฐานข้อมูล
sql.connect(dbConfig).then(pool => {
    if (pool.connected) {
        console.log('Connected to the database.');
    }
}).catch(err => {
    console.error('Database connection error:', err);
});

// ฟังก์ชันที่สามารถนำมาใช้ซ้ำได้สำหรับการดำเนินการคำสั่ง SQL
function executeQuery(query, inputs, callback) {
    const request = new sql.Request();
    
    // ตั้งค่าข้อมูลที่ต้องการในคำสั่ง SQL
    inputs.forEach(input => {
        request.input(input.name, input.type, input.value);
    });
    
    // ดำเนินการคำสั่ง SQL
    request.query(query, (err, result) => {
        if (err) {
            console.error('Error executing query:', err.message, err.code, err);
            return callback(err, null);
        }
        callback(null, result);
    });
}

app.post('/register', async (req, res) => {
    const { img, FL_name, Nickname, Birthday, Province, Email, Password, Phone, Facebook, ID_Line } = req.body;
        
    if (!img || !FL_name || !Nickname || !Birthday || !Province || !Email || !Password || !Phone || !Facebook || !ID_Line) {
        return res.status(400).send('All fields are required.');
    }

    try {
        const hashedPassword = await bcrypt.hash(Password, 10);
        
        const request = new sql.Request();
        
        request.input('img', sql.VarChar, img);
        request.input('FL_name', sql.VarChar, FL_name);
        request.input('Nickname', sql.VarChar, Nickname);
        request.input('Birthday', sql.VarChar, Birthday); 
        request.input('Province', sql.VarChar, Province);
        request.input('Email', sql.VarChar, Email);
        request.input('Password', sql.VarChar, hashedPassword); 
        request.input('Phone', sql.VarChar, Phone);
        request.input('Facebook', sql.VarChar, Facebook);
        request.input('ID_Line', sql.VarChar, ID_Line);
            
        
        const query = `
            INSERT INTO Users (img, FL_name, Nickname, Birthday, Province, Email, Password, Phone, Facebook, ID_Line)
            VALUES (@img, @FL_name, @Nickname, @Birthday, @Province, @Email, @Password, @Phone, @Facebook, @ID_Line);
        `;
            
        request.query(query, (err, result) => {
            if (err) {
                console.error('Error executing query:', err);
                res.status(500).send('Server error. Please try again later.');
            } else {
                console.log('Data inserted successfully.');
                res.send('Data inserted successfully.');
            }
        });
    } catch (err) {
        console.error('Error hashing password:', err);
        res.status(500).send('Server error. Please try again later.');
    }
});


// Endpoint สำหรับการเข้าสู่ระบบ
app.post('/login', (req, res) => {
    const { Email, Password } = req.body;
        
    if (!Email || !Password) {
        return res.status(400).send('Email and Password are required.');
    }

    const query = "SELECT ID_user, Password FROM Users WHERE Email = @Email";
    const inputs = [
        { name: 'Email', type: sql.VarChar, value: Email }
    ];
    
    executeQuery(query, inputs, async (err, result) => {
        if (err) {
            console.error('Login query error:', err.message, err.code, err);
            return res.status(500).send('Server error. Please try again later.');
        }
        if (result.recordset.length === 0) {
            return res.status(401).send('Invalid email or password.');
        }

        const user = result.recordset[0];
        const passwordMatch = await bcrypt.compare(Password, user.Password);
        if (!passwordMatch) {
            return res.status(401).send('Invalid email or password.');
        }
        
        console.log('Login successful.');
        const userId = user.ID_user;
    
        // สร้าง Token
        const token = jwt.sign({ id: userId }, secretKey, { expiresIn: '1h' });
        res.json({ token });
    });
});


app.get('/users/:ID_user', (req, res) => {
    const { ID_user } = req.params;
    
    if (!ID_user) {
        return res.status(400).send('ID_user is required.');
    }

    const query = ` SELECT  img, FL_name, Nickname, Birthday, Province, Phone, Facebook, ID_Line, Email, Password
                    FROM    Users 
                    WHERE   ID_user = @ID_user`;
    const inputs = [
        { name: 'ID_user', type: sql.Int, value: ID_user }
    ];
    
    executeQuery(query, inputs, (err, result) => {
        if (err) {
            console.error('Get user query error:', err.message, err.code, err);
            return res.status(500).send('Server error. Please try again later.');
        }
        if (result.recordset.length === 0) {
            return res.status(404).send('User not found.');
        }
        
        res.json(result.recordset[0]);
    });
});

// เริ่มต้นเซิร์ฟเวอร์
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
