const express = require('express');
const cors = require('cors');
const pool = require('./db');
const jwt = require('jsonwebtoken'); 
const bcrypt = require('bcryptjs'); 
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000; 

const JWT_SECRET = process.env.JWT_SECRET || 'ganti_dengan_secret_key_yang_sangat_kuat'; 

app.use(cors()); 
app.use(express.json()); 

// --- MIDDLEWARE OTENTIKASI DAN OTORISASI ---
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; 
    
    if (token == null) return res.status(401).json({ message: 'Akses ditolak. Token tidak tersedia.' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ message: 'Token tidak valid.' });
        req.user = user;
        next();
    });
};

const isAdmin = (req, res, next) => {
    const role = req.user.role;
    if (role === 'admin' || role === 'superuser' || role === 'entry_admin') { 
        return next();
    }
    return res.status(403).json({ message: 'Akses ditolak. Hanya Admin/Superuser yang diizinkan.' });
};

const canEdit = async (req, res, next) => {
    // Amankan req.body dari undefined
    const requestBody = req.body || {}; 
    const reportId = req.params.id; // ID Laporan untuk PUT/DELETE

    // 1. Dapatkan Unit ID yang relevan. Prioritas: Body > URL Params.
    let unitId = requestBody.id_unit;

    // 2. Jika Unit ID tidak ditemukan di body (kasus DELETE), kita cari di DB menggunakan ID Laporan
    if (!unitId && reportId) {
        // Asumsi: Kita mencari di tabel LaporanHarian untuk contoh ini.
        // Dalam implementasi nyata, Anda perlu menentukan tabel mana (LaporanHarian/Penjumboan/Pemuatan)
        try {
            const [result] = await pool.query('SELECT id_unit FROM LaporanHarian WHERE id_laporan = ?', [reportId]);
            unitId = result[0]?.id_unit;
        } catch (e) {
            console.error('Error lookup unitId for DELETE:', e);
            // Lanjutkan, biarkan pengecekan di bawah gagal jika ID unit tidak ditemukan
        }
    }
    
    const userGroups = req.user?.allowed_groups;
    const userRole = req.user?.role;

    // 3. BYPASS UTAMA UNTUK SUPERUSER
    if (userRole === 'superuser') return next(); 

    // 4. PENGECEKAN ROLE
    if (userRole !== 'entry_admin') {
         return res.status(403).json({ message: 'Akses ditolak. Peran tidak memiliki izin input.' });
    }

    // 5. PENGECEKAN DATA GROUP (SETELAH ID UNIT DIPEROLEH)
    if (!unitId || !userGroups) {
        return res.status(400).json({ message: 'Payload unit kerja atau izin grup tidak lengkap.' });
    }

    try {
        const [groupResult] = await pool.query(`
            SELECT pg.group_name
            FROM UnitKerja uk
            JOIN ProductionGroup pg ON uk.group_id = pg.group_id
            WHERE uk.id_unit = ?
        `, [unitId]);

        const unitGroupName = groupResult[0]?.group_name;

        if (!unitGroupName) {
            return res.status(400).json({ message: 'Unit Kerja tidak valid atau tidak terdaftar.' });
        }

        const allowedGroupsArray = userGroups.split(',');
        
        if (allowedGroupsArray.includes(unitGroupName)) {
            return next();
        }

        return res.status(403).json({ message: `Akses ditolak. User hanya diizinkan untuk menginput data di grup: ${userGroups}.` });

    } catch (err) {
        console.error('Error in canEdit middleware:', err);
        return res.status(500).json({ message: 'Kesalahan server saat memverifikasi izin.' });
    }
};
const fetchRilisProduksiData = async (groupName, year) => {
    const currentYear = parseInt(year);

    const rilisQuery = `
        SELECT 
            uk.nama_unit,
            MONTH(lpp.tanggal) AS month,
            COALESCE(SUM(lpp.produksi_ton), 0) AS total_produksi_ton
        FROM LaporanHarian lpp
        JOIN UnitKerja uk ON lpp.id_unit = uk.id_unit
        JOIN ProductionGroup pg ON uk.group_id = pg.group_id
        WHERE pg.group_name = ? AND YEAR(lpp.tanggal) = ?
        GROUP BY uk.nama_unit, month
        ORDER BY month ASC
    `;

    const [rilisDataRaw] = await pool.query(rilisQuery, [groupName, currentYear]);
    
    // --- Logika Restrukturisasi Data (Pivoting) ---
    const monthlyAggregatedData = {};
    const monthNamesAbbr = ["JAN", "FEB", "MAR", "APR", "MEI", "JUN", "JUL", "AGU", "SEP", "OKT", "NOV", "DES"];

    rilisDataRaw.forEach(item => {
        const monthKey = item.month;
        const unitName = item.nama_unit;
        
        if (!monthlyAggregatedData[monthKey]) {
            monthlyAggregatedData[monthKey] = { 
                month: monthKey, 
                monthLabel: monthNamesAbbr[monthKey - 1]
            };
        }
        monthlyAggregatedData[monthKey][unitName] = parseFloat(item.total_produksi_ton);
    });

    return Object.values(monthlyAggregatedData).sort((a, b) => a.month - b.month);
};

// API untuk Rilis Produksi PABRIK
app.get('/api/produksi/pabrik/rilis/:year', async (req, res) => {
    try {
        const data = await fetchRilisProduksiData('Pabrik', req.params.year);
        res.json(data);
    } catch (err) {
        console.error('Error fetching Pabrik Rilis data:', err);
        res.status(500).json({ message: 'Server error saat mengambil data Rilis Pabrik.' });
    }
});

// API untuk Rilis Produksi BKS
app.get('/api/produksi/bks/rilis/:year', async (req, res) => {
    try {
        const data = await fetchRilisProduksiData('BKS', req.params.year);
        res.json(data);
    } catch (err) {
        console.error('Error fetching BKS Rilis data:', err);
        res.status(500).json({ message: 'Server error saat mengambil data Rilis BKS.' });
    }
});
// ------------------------------------------------------------------
// AUTH & MASTER DATA ENDPOINTS
// ------------------------------------------------------------------

// [POST] Endpoint Login
app.post('/api/auth/login', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ message: 'Username dan password wajib diisi.' });
    }

    try {
        const [users] = await pool.query('SELECT * FROM Users WHERE username = ?', [username]);
        const user = users[0];

        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ message: 'Username atau password salah.' });
        }

        const token = jwt.sign(
            { id: user.id, username: user.username, role: user.role, allowed_groups: user.allowed_groups },
            JWT_SECRET,
            { expiresIn: '1h' }
        );

        res.json({ token, user: { id: user.id, username: user.username, role: user.role, allowed_groups: user.allowed_groups } });

    } catch (err) {
        console.error('Error saat login:', err);
        res.status(500).json({ message: 'Terjadi kesalahan server.' });
    }
});

// [GET] Mengambil semua Unit Kerja (PUBLIK)
app.get('/api/units', async (req, res) => {
    try {
        const query = `
            SELECT uk.id_unit, uk.nama_unit, pg.group_name
            FROM UnitKerja uk
            JOIN ProductionGroup pg ON uk.group_id = pg.group_id;
        `;
        const [rows] = await pool.query(query);
        res.json(rows);
    } catch (err) {
        console.error('Error fetching units:', err);
        res.status(500).json({ message: 'Server error saat mengambil unit kerja.' });
    }
});

// ------------------------------------------------------------------
// PRODUKSI ENDPOINTS (LaporanHarian - Hambatan Based)
// ------------------------------------------------------------------

// [POST] Membuat Laporan Harian (PRODUKSI) (DILINDUNGI GROUP ADMIN)
app.post('/api/laporan', authenticateToken, canEdit, async (req, res) => {
    const { tanggal, id_unit, produksi_ton, jam_operasi, h_proses, h_listrik, h_mekanik, h_operator, h_hujan, h_kapal, h_pmc } = req.body;

    const query = `
        INSERT INTO LaporanHarian (tanggal, id_unit, produksi_ton, jam_operasi, h_proses, h_listrik, h_mekanik, h_operator, h_hujan, h_kapal, h_pmc) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `;
    const values = [tanggal, id_unit, produksi_ton, jam_operasi, h_proses, h_listrik, h_mekanik, h_operator, h_hujan, h_kapal, h_pmc];

    try {
        await pool.query(query, values);
        res.status(201).json({ message: 'Laporan Produksi berhasil ditambahkan.' });
    } catch (err) {
        console.error('Error inserting report:', err);
        if (err.errno === 1062) { 
             return res.status(409).json({ message: 'Gagal: Laporan Produksi untuk tanggal dan unit ini sudah ada.' });
        }
        res.status(500).json({ message: 'Gagal menambahkan laporan karena kesalahan server.' });
    }
});

// [GET] Mengambil SEMUA Laporan Harian (PRODUKSI) (DILINDUNGI ADMIN)
app.get('/api/laporan/all', authenticateToken, isAdmin, async (req, res) => {
    try {
        const query = `
            SELECT lh.*, uk.nama_unit 
            FROM LaporanHarian lh 
            LEFT JOIN UnitKerja uk ON lh.id_unit = uk.id_unit 
            ORDER BY lh.tanggal DESC, lh.id_laporan DESC
        `;
        const [rows] = await pool.query(query);
        res.json(rows);
    } catch (err) {
        console.error('Error fetching all reports:', err);
        res.status(500).json({ message: 'Server error saat mengambil semua laporan.' });
    }
});

// [PUT] Memperbarui Laporan Harian (PRODUKSI) (DILINDUNGI GROUP ADMIN)
app.put('/api/laporan/:id', authenticateToken, canEdit, async (req, res) => {
    const { id } = req.params;
    const { tanggal, id_unit, produksi_ton, jam_operasi, h_proses, h_listrik, h_mekanik, h_operator, h_hujan, h_kapal, h_pmc } = req.body;
    
    // Pastikan SEMUA kolom dipisahkan dengan koma dan diakhiri sebelum WHERE
    const query = `
        UPDATE LaporanHarian SET 
            tanggal = ?, 
            id_unit = ?, 
            produksi_ton = ?, 
            jam_operasi = ?, 
            h_proses = ?, 
            h_listrik = ?, 
            h_mekanik = ?, 
            h_operator = ?, 
            h_hujan = ?, 
            h_kapal = ?, 
            h_pmc = ? 
        WHERE id_laporan = ?
    `;
    const values = [tanggal, id_unit, produksi_ton, jam_operasi, h_proses, h_listrik, h_mekanik, h_operator, h_hujan, h_kapal, h_pmc, id];
    
    try {
        const [result] = await pool.query(query, values);
        
        if (result.affectedRows === 0) { 
            return res.status(404).json({ message: 'Laporan tidak ditemukan.' }); 
        }
        
        res.json({ message: 'Laporan berhasil diperbarui.' });
        
    } catch (err) { 
        console.error('Error updating report:', err); 
        
        if (err.errno === 1062) {
            return res.status(409).json({ message: 'Gagal: Kombinasi Tanggal dan Unit Kerja sudah ada pada laporan lain.' });
        }
        
        res.status(500).json({ message: 'Gagal memperbarui laporan.' }); 
    }
});

// [DELETE] Menghapus Laporan Harian (PRODUKSI) (DILINDUNGI GROUP ADMIN)
app.delete('/api/laporan/:id', authenticateToken, canEdit, async (req, res) => {
    const { id } = req.params;
    try {
        const [result] = await pool.query('DELETE FROM LaporanHarian WHERE id_laporan = ?', [id]);
        if (result.affectedRows === 0) { return res.status(404).json({ message: 'Laporan tidak ditemukan.' }); }
        res.json({ message: 'Laporan berhasil dihapus.' });
    } catch (err) { console.error('Error deleting report:', err); res.status(500).json({ message: 'Gagal menghapus laporan.' }); }
});

// ------------------------------------------------------------------
// PENJUMBOAN ENDPOINTS (LaporanPenjumboan - Shift Based)
// ------------------------------------------------------------------

// [GET] Mengambil Semua Laporan Penjumboan (HANYA ADMIN)
app.get('/api/penjumboan/laporan/all', authenticateToken, isAdmin, async (req, res) => {
    try {
        const query = `
            SELECT lp.*, uk.nama_unit 
            FROM LaporanPenjumboan lp 
            LEFT JOIN UnitKerja uk ON lp.id_unit = uk.id_unit 
            ORDER BY lp.tanggal DESC, lp.id_laporan DESC
        `;
        const [rows] = await pool.query(query);
        res.json(rows);
    } catch (err) {
        console.error('Error fetching all penjumboan reports:', err);
        res.status(500).json({ message: 'Server error saat mengambil laporan Penjumboan.' });
    }
});

// [POST] Input Laporan Penjumboan (HANYA ADMIN)
app.post('/api/penjumboan/laporan', authenticateToken, canEdit, async (req, res) => {
    const { tanggal, id_unit, shift_1_ton, shift_2_ton, shift_3_ton, target } = req.body;
    
    const query = `
        INSERT INTO LaporanPenjumboan (tanggal, id_unit, shift_1_ton, shift_2_ton, shift_3_ton, target) 
        VALUES (?, ?, ?, ?, ?, ?)
    `;
    const values = [tanggal, id_unit, shift_1_ton, shift_2_ton, shift_3_ton, target];

    try {
        await pool.query(query, values);
        res.status(201).json({ message: 'Laporan Penjumboan berhasil ditambahkan.' });
    } catch (err) {
        if (err.errno === 1062) { 
             return res.status(409).json({ message: 'Gagal: Laporan Penjumboan untuk tanggal dan unit ini sudah ada.' });
        }
        console.error('Error inserting penjumboan report:', err);
        res.status(500).json({ message: 'Gagal menambahkan laporan Penjumboan karena kesalahan server.' });
    }
});

// [PUT] Memperbarui Laporan Penjumboan (HANYA ADMIN)
app.put('/api/penjumboan/laporan/:id', authenticateToken, canEdit, async (req, res) => {
    const { id } = req.params;
    const { tanggal, id_unit, shift_1_ton, shift_2_ton, shift_3_ton, target } = req.body;
    
    const query = `UPDATE LaporanPenjumboan SET tanggal = ?, id_unit = ?, shift_1_ton = ?, shift_2_ton = ?, shift_3_ton = ?, target = ? WHERE id_laporan = ?`;
    const values = [tanggal, id_unit, shift_1_ton, shift_2_ton, shift_3_ton, target, id];

    try {
        const [result] = await pool.query(query, values);
        if (result.affectedRows === 0) { return res.status(404).json({ message: 'Laporan Penjumboan tidak ditemukan.' }); }
        res.json({ message: 'Laporan Penjumboan berhasil diperbarui.' });
    } catch (err) {
        console.error('Error updating penjumboan report:', err);
        res.status(500).json({ message: 'Gagal memperbarui laporan Penjumboan.' });
    }
});

// [DELETE] Menghapus Laporan Penjumboan (HANYA ADMIN)
app.delete('/api/penjumboan/laporan/:id', authenticateToken, canEdit, async (req, res) => {
    const { id } = req.params;
    try {
        const [result] = await pool.query('DELETE FROM LaporanPenjumboan WHERE id_laporan = ?', [id]);
        if (result.affectedRows === 0) { return res.status(404).json({ message: 'Laporan Penjumboan tidak ditemukan.' }); }
        res.json({ message: 'Laporan berhasil dihapus.' });
    } catch (err) { console.error('Error deleting penjumboan report:', err); res.status(500).json({ message: 'Gagal menghapus laporan Penjumboan.' }); }
});

// ------------------------------------------------------------------
// PEMUATAN ENDPOINTS (LaporanPemuatan - Ton/Jam Muat Based)
// ------------------------------------------------------------------

// [GET] Mengambil Semua Laporan Pemuatan (HANYA ADMIN)
app.get('/api/pemuatan/laporan/all', authenticateToken, isAdmin, async (req, res) => {
    try {
        const query = `
            SELECT lp.*, uk.nama_unit 
            FROM LaporanPemuatan lp 
            LEFT JOIN UnitKerja uk ON lp.id_unit = uk.id_unit 
            ORDER BY lp.tanggal DESC, lp.id_laporan DESC
        `;
        const [rows] = await pool.query(query);
        res.json(rows);
    } catch (err) {
        console.error('Error fetching all pemuatan reports:', err);
        res.status(500).json({ message: 'Server error saat mengambil laporan Pemuatan.' });
    }
});

// [POST] Input Laporan Pemuatan (HANYA ADMIN)
app.post('/api/pemuatan/laporan', authenticateToken, canEdit, async (req, res) => {
    const { tanggal, id_unit, jam_muat, ton_muat, target } = req.body;
    
    const query = `
        INSERT INTO LaporanPemuatan (tanggal, id_unit, jam_muat, ton_muat, target) 
        VALUES (?, ?, ?, ?, ?)
    `;
    const values = [tanggal, id_unit, jam_muat, ton_muat, target];

    try {
        await pool.query(query, values);
        res.status(201).json({ message: 'Laporan Pemuatan berhasil ditambahkan oleh Admin.' });
    } catch (err) {
        if (err.errno === 1062) { 
             return res.status(409).json({ message: 'Gagal: Laporan Pemuatan untuk tanggal dan unit ini sudah ada.' });
        }
        console.error('Error inserting pemuatan report:', err);
        res.status(500).json({ message: 'Gagal menambahkan laporan Pemuatan karena kesalahan server.' });
    }
});

// [PUT] Memperbarui Laporan Pemuatan (HANYA ADMIN)
app.put('/api/pemuatan/laporan/:id', authenticateToken, canEdit, async (req, res) => {
    const { id } = req.params;
    const { tanggal, id_unit, jam_muat, ton_muat, target } = req.body;
    
    const query = `UPDATE LaporanPemuatan SET tanggal = ?, id_unit = ?, jam_muat = ?, ton_muat = ?, target = ? WHERE id_laporan = ?`;
    const values = [tanggal, id_unit, jam_muat, ton_muat, target, id];

    try {
        const [result] = await pool.query(query, values);
        if (result.affectedRows === 0) { return res.status(404).json({ message: 'Laporan Pemuatan tidak ditemukan.' }); }
        res.json({ message: 'Laporan Pemuatan berhasil diperbarui oleh Admin.' });
    } catch (err) { console.error('Error updating pemuatan report:', err); res.status(500).json({ message: 'Gagal memperbarui laporan Pemuatan.' }); }
});

// [DELETE] Menghapus Laporan Pemuatan (HANYA ADMIN)
app.delete('/api/pemuatan/laporan/:id', authenticateToken, canEdit, async (req, res) => {
    const { id } = req.params;
    try {
        const [result] = await pool.query('DELETE FROM LaporanPemuatan WHERE id_laporan = ?', [id]);
        if (result.affectedRows === 0) { return res.status(404).json({ message: 'Laporan Pemuatan tidak ditemukan.' }); }
        res.json({ message: 'Laporan berhasil dihapus oleh Admin.' });
    } catch (err) { console.error('Error deleting pemuatan report:', err); res.status(500).json({ message: 'Gagal menghapus laporan Pemuatan.' }); }
});

// ------------------------------------------------------------------
// PACKING PLANT ENDPOINTS (LaporanPackingPlant)
// ------------------------------------------------------------------

// [GET] Mengambil Semua Laporan Packing Plant (HANYA ADMIN)
app.get('/api/packing-plant/laporan/all', authenticateToken, isAdmin, async (req, res) => {
    try {
        const query = `
            SELECT lp.*, uk.nama_unit 
            FROM LaporanPackingPlant lp 
            LEFT JOIN UnitKerja uk ON lp.id_unit = uk.id_unit 
            ORDER BY lp.tanggal DESC, lp.id_laporan DESC
        `;
        const [rows] = await pool.query(query);
        res.json(rows);
    } catch (err) {
        console.error('Error fetching all packing plant reports:', err);
        res.status(500).json({ message: 'Server error saat mengambil laporan Packing Plant.' });
    }
});

// [POST] Input Laporan Packing Plant (HANYA ADMIN)
app.post('/api/packing-plant/laporan', authenticateToken, canEdit, async (req, res) => {
    const { tanggal, id_unit, ton_muat, target, target_rkp } = req.body;
    
    const query = `
        INSERT INTO LaporanPackingPlant (tanggal, id_unit, ton_muat, target, target_rkp) 
        VALUES (?, ?, ?, ?, ?)
    `;
    const values = [tanggal, id_unit, ton_muat, target, target_rkp];

    try {
        await pool.query(query, values);
        res.status(201).json({ message: 'Laporan Packing Plant berhasil ditambahkan.' });
    } catch (err) {
        if (err.errno === 1062) { 
             return res.status(409).json({ message: 'Gagal: Laporan Packing Plant untuk tanggal dan unit ini sudah ada.' });
        }
        console.error('Error inserting packing plant report:', err);
        res.status(500).json({ message: 'Gagal menambahkan laporan Packing Plant karena kesalahan server.' });
    }
});

// [PUT] Memperbarui Laporan Packing Plant (HANYA ADMIN)
app.put('/api/packing-plant/laporan/:id', authenticateToken, canEdit, async (req, res) => {
    const { id } = req.params;
    const { tanggal, id_unit, ton_muat, target, target_rkp } = req.body;
    
    const query = `UPDATE LaporanPackingPlant SET tanggal = ?, id_unit = ?, ton_muat = ?, target = ?, target_rkp = ? WHERE id_laporan = ?`;
    const values = [tanggal, id_unit, ton_muat, target, target_rkp, id];

    try {
        const [result] = await pool.query(query, values);
        if (result.affectedRows === 0) { return res.status(404).json({ message: 'Laporan Packing Plant tidak ditemukan.' }); }
        res.json({ message: 'Laporan Packing Plant berhasil diperbarui.' });
    } catch (err) { console.error('Error updating packing plant report:', err); res.status(500).json({ message: 'Gagal memperbarui laporan Packing Plant.' }); }
});

// [DELETE] Menghapus Laporan Packing Plant (HANYA ADMIN)
app.delete('/api/packing-plant/laporan/:id', authenticateToken, canEdit, async (req, res) => {
    const { id } = req.params;
    try {
        const [result] = await pool.query('DELETE FROM LaporanPackingPlant WHERE id_laporan = ?', [id]);
        if (result.affectedRows === 0) { return res.status(404).json({ message: 'Laporan Packing Plant tidak ditemukan.' }); }
        res.json({ message: 'Laporan berhasil dihapus.' });
    } catch (err) { console.error('Error deleting packing plant report:', err); res.status(500).json({ message: 'Gagal menghapus laporan Packing Plant.' }); }
});
app.get('/api/packing-plant/rilis/:year', async (req, res) => {
    const { year } = req.params;
    const currentYear = parseInt(year);

    const rilisQuery = `
        SELECT 
            uk.nama_unit,
            MONTH(lpp.tanggal) AS month,
            COALESCE(SUM(lpp.ton_muat), 0) AS total_muat_ton
        FROM LaporanPackingPlant lpp
        JOIN UnitKerja uk ON lpp.id_unit = uk.id_unit
        JOIN ProductionGroup pg ON uk.group_id = pg.group_id
        WHERE pg.group_name = 'Packing Plant' AND YEAR(lpp.tanggal) = ?
        GROUP BY uk.nama_unit, month
        ORDER BY month ASC
    `;

    try {
        const [rilisDataRaw] = await pool.query(rilisQuery, [currentYear]);
        
        // Data perlu di-restrukturisasi agar Recharts dapat membuat Grouped Bar Chart
        // [ {month: 1, "PP Makassar": 1000, "PP Palu": 500}, ... ]
        const monthlyAggregatedData = {};

        rilisDataRaw.forEach(item => {
            const monthKey = item.month;
            const unitName = item.nama_unit;
            
            if (!monthlyAggregatedData[monthKey]) {
                monthlyAggregatedData[monthKey] = { 
                    month: monthKey, 
                    monthLabel: ['JAN', 'FEB', 'MAR', 'APR', 'MEI', 'JUN', 'JUL', 'AGU', 'SEP', 'OKT', 'NOV', 'DES'][monthKey - 1]
                };
            }
            monthlyAggregatedData[monthKey][unitName] = parseFloat(item.total_muat_ton);
        });

        const finalData = Object.values(monthlyAggregatedData).sort((a, b) => a.month - b.month);
        res.json(finalData);

    } catch (err) {
        console.error('Error fetching Rilis Packing Plant data:', err);
        res.status(500).json({ message: 'Server error saat mengambil data rilis Packing Plant.' });
    }
});

// ------------------------------------------------------------------
// DASHBOARD AGGREGATION ENDPOINTS (PUBLIK)
// ------------------------------------------------------------------

// API untuk Dashboard Produksi (LaporanHarian)
app.get('/api/dashboard/:unitId/:year/:month', async (req, res) => {
    const { unitId, year, month } = req.params;
    
    const currentYear = parseInt(year);
    const currentMonth = parseInt(month);

    // 1. Data Harian
    const dailyQuery = `
        SELECT tanggal, produksi_ton, jam_operasi, total_hambatan, 900 AS target
        FROM LaporanHarian 
        WHERE id_unit = ? AND MONTH(tanggal) = ? AND YEAR(tanggal) = ?   
        ORDER BY CAST(tanggal AS DATETIME) ASC
    `;

    // 2. Data Hambatan Bulanan (MTD)
    const monthlyHambatanQuery = `
        SELECT COALESCE(SUM(h_proses), 0) as h_proses, COALESCE(SUM(h_listrik), 0) as h_listrik, COALESCE(SUM(h_mekanik), 0) as h_mekanik, COALESCE(SUM(h_operator), 0) as h_operator, COALESCE(SUM(h_hujan), 0) as h_hujan, COALESCE(SUM(h_kapal), 0) as h_kapal, COALESCE(SUM(h_pmc), 0) as h_pmc
        FROM LaporanHarian
        WHERE id_unit = ? AND MONTH(tanggal) = ? AND YEAR(tanggal) = ?
    `;
    
    // 3. Data Bulanan (Produksi 12 Bulan Terakhir)
    const monthlyQuery = `
        SELECT YEAR(tanggal) AS year, MONTH(tanggal) AS month, COALESCE(SUM(CAST(produksi_ton AS DECIMAL(10, 2))), 0) AS total_produksi_ton, 26350 AS target_bulanan 
        FROM LaporanHarian
        WHERE id_unit = ?
        GROUP BY year, month
        ORDER BY year DESC, month DESC
        LIMIT 12
    `;

    // 4. Total Produksi BULAN YANG DIPILIH
    const monthlyTotalQuery = `
        SELECT COALESCE(SUM(CAST(produksi_ton AS DECIMAL(10, 2))), 0) AS total_produksi_mtd
        FROM LaporanHarian
        WHERE id_unit = ? AND MONTH(tanggal) = ? AND YEAR(tanggal) = ?
    `;

    try {
        const [dailyData] = await pool.query(dailyQuery, [unitId, currentMonth, currentYear]); 
        const [hambatanData] = await pool.query(monthlyHambatanQuery, [unitId, currentMonth, currentYear]);
        const [monthlyData] = await pool.query(monthlyQuery, [unitId]);
        const [monthlyTotal] = await pool.query(monthlyTotalQuery, [unitId, currentMonth, currentYear]);

        res.json({
            dailyReport: dailyData,
            hambatanSummary: hambatanData[0] || {},
            monthlyReport: monthlyData.reverse(),
            totalProductionMTD: monthlyTotal[0]?.total_produksi_mtd || 0
        });

    } catch (err) {
        console.error('Error fetching dashboard data:', err);
        res.status(500).json({ message: 'Server error saat mengambil data dashboard.' });
    }
});

// API untuk Dashboard Penjumboan
app.get('/api/penjumboan/dashboard/:unitId/:year/:month', async (req, res) => {
    const { unitId, year, month } = req.params;
    
    const currentYear = parseInt(year);
    const currentMonth = parseInt(month);

    // Query Total Produksi Penjumboan (MTD)
    const monthlyTotalPenjumboanQuery = `
        SELECT COALESCE(SUM(total_produksi), 0) AS total_produksi_mtd, COALESCE(SUM(target), 0) AS total_target_mtd
        FROM LaporanPenjumboan
        WHERE id_unit = ? AND MONTH(tanggal) = ? AND YEAR(tanggal) = ?
    `;

    // Query Harian Penjumboan (untuk chart harian shift/total)
    const dailyPenjumboanQuery = `
        SELECT tanggal, shift_1_ton, shift_2_ton, shift_3_ton, total_produksi, target
        FROM LaporanPenjumboan
        WHERE id_unit = ? AND MONTH(tanggal) = ? AND YEAR(tanggal) = ?
        ORDER BY CAST(tanggal AS DATETIME) ASC
    `;
    
    // Query Bulanan Penjumboan (Total produksi 12 bulan)
    const monthlyPenjumboanQuery = `
        SELECT YEAR(tanggal) AS year, MONTH(tanggal) AS month, COALESCE(SUM(total_produksi), 0) AS total_produksi_ton, COALESCE(SUM(target), 0) AS total_target_bulanan 
        FROM LaporanPenjumboan
        WHERE id_unit = ?
        GROUP BY year, month
        ORDER BY year DESC, month DESC
        LIMIT 12
    `;

    try {
        const [dailyData] = await pool.query(dailyPenjumboanQuery, [unitId, currentMonth, currentYear]); 
        const [monthlyData] = await pool.query(monthlyPenjumboanQuery, [unitId]);
        const [monthlyTotal] = await pool.query(monthlyTotalPenjumboanQuery, [unitId, currentMonth, currentYear]);

        res.json({
            dailyReport: dailyData,
            monthlyReport: monthlyData.reverse(),
            totalProductionMTD: monthlyTotal[0]?.total_produksi_mtd || 0
        });

    } catch (err) {
        console.error('Error fetching penjumboan dashboard data:', err);
        res.status(500).json({ message: 'Server error saat mengambil data Penjumboan dashboard.' });
    }
});


// API untuk Dashboard Pemuatan
app.get('/api/pemuatan/dashboard/:unitId/:year/:month', async (req, res) => {
    const { unitId, year, month } = req.params;
    
    const currentYear = parseInt(year);
    const currentMonth = parseInt(month);

    // Query Total Produksi Pemuatan (MTD)
    const monthlyTotalPemuatanQuery = `
        SELECT COALESCE(SUM(ton_muat), 0) AS total_produksi_mtd
        FROM LaporanPemuatan
        WHERE id_unit = ? AND MONTH(tanggal) = ? AND YEAR(tanggal) = ?
    `;

    // Query Harian Pemuatan (untuk chart harian)
    const dailyPemuatanQuery = `
        SELECT tanggal, jam_muat, ton_muat, target
        FROM LaporanPemuatan
        WHERE id_unit = ? AND MONTH(tanggal) = ? AND YEAR(tanggal) = ?
        ORDER BY CAST(tanggal AS DATETIME) ASC
    `;
    
    // Query Bulanan Pemuatan (Total muat 12 bulan)
    const monthlyPemuatanQuery = `
        SELECT YEAR(tanggal) AS year, MONTH(tanggal) AS month, COALESCE(SUM(ton_muat), 0) AS total_ton_muat, COALESCE(SUM(target), 0) AS total_target_bulanan 
        FROM LaporanPemuatan
        WHERE id_unit = ?
        GROUP BY year, month
        ORDER BY year DESC, month DESC
        LIMIT 12
    `;

    try {
        const [dailyDataRaw] = await pool.query(dailyPemuatanQuery, [unitId, currentMonth, currentYear]); 
        
        // --- LOGIC UNTUK PEMUATAN S.D (CUMULATIVE SUM) ---
        let cumulativeSum = 0;
        const dailyDataProcessed = dailyDataRaw.map(item => {
            const tonMuat = parseFloat(item.ton_muat) || 0;
            cumulativeSum += tonMuat;
            
            return {
                ...item,
                ton_muat: tonMuat,
                target: parseFloat(item.target) || 0,
                pemuatan_sd: cumulativeSum // Field baru: total kumulatif
            };
        });
        // --- END LOGIC UNTUK PEMUATAN S.D (CUMULATIVE SUM) ---

        const [monthlyData] = await pool.query(monthlyPemuatanQuery, [unitId]);
        const [monthlyTotal] = await pool.query(monthlyTotalPemuatanQuery, [unitId, currentMonth, currentYear]);

        res.json({
            dailyReport: dailyDataProcessed,
            monthlyReport: monthlyData.reverse(),
            totalProductionMTD: monthlyTotal[0]?.total_produksi_mtd || 0
        });

    } catch (err) {
        console.error('Error fetching pemuatan dashboard data:', err);
        res.status(500).json({ message: 'Server error saat mengambil data Pemuatan dashboard.' });
    }
});

// API untuk Dashboard Packing Plant
app.get('/api/packing-plant/dashboard/:unitId/:year/:month', async (req, res) => {
    const { unitId, year, month } = req.params;
    
    const currentYear = parseInt(year);
    const currentMonth = parseInt(month);

    const dailyQuery = `
        SELECT tanggal, ton_muat, target, target_rkp
        FROM LaporanPackingPlant
        WHERE id_unit = ? AND MONTH(tanggal) = ? AND YEAR(tanggal) = ?
        ORDER BY CAST(tanggal AS DATETIME) ASC
    `;

    const monthlyTotalQuery = `
        SELECT COALESCE(SUM(ton_muat), 0) AS total_produksi_mtd
        FROM LaporanPackingPlant
        WHERE id_unit = ? AND MONTH(tanggal) = ? AND YEAR(tanggal) = ?
    `;

    const monthlyQuery = `
        SELECT YEAR(tanggal) AS year, MONTH(tanggal) AS month, COALESCE(SUM(ton_muat), 0) AS total_produksi, AVG(target_rkp) AS target_rkp_bulanan 
        FROM LaporanPackingPlant
        WHERE id_unit = ?
        GROUP BY year, month
        ORDER BY year DESC, month DESC
        LIMIT 12
    `;

    try {
        const [dailyDataRaw] = await pool.query(dailyQuery, [unitId, currentMonth, currentYear]); 
        
        // LOGIC PEMUATAN S.D. (CUMULATIVE SUM)
        let cumulativeSum = 0;
        const dailyDataProcessed = dailyDataRaw.map(item => {
            const tonMuat = parseFloat(item.ton_muat) || 0;
            cumulativeSum += tonMuat;
            
            return {
                ...item,
                ton_muat: tonMuat,
                target: parseFloat(item.target) || 0,
                target_rkp_daily: parseFloat(item.target_rkp) || 0,
                pemuatan_sd: cumulativeSum // Cumulative field
            };
        });
        
        const [monthlyData] = await pool.query(monthlyQuery, [unitId]);
        const [monthlyTotal] = await pool.query(monthlyTotalQuery, [unitId, currentMonth, currentYear]);

        res.json({
            dailyReport: dailyDataProcessed,
            monthlyReport: monthlyData.reverse(),
            totalProductionMTD: monthlyTotal[0]?.total_produksi_mtd || 0
        });

    } catch (err) {
        console.error('Error fetching packing plant dashboard data:', err);
        res.status(500).json({ message: 'Server error saat mengambil data Packing Plant dashboard.' });
    }
});


// --- 4. START SERVER ---
app.listen(PORT, () => {
    console.log(`Server Express berjalan di http://localhost:${PORT}`);
});