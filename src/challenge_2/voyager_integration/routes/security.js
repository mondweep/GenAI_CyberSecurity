const express = require('express');
const router = express.Router();
const { spawn } = require('child_process');
const path = require('path');

// Path to your Python script - going up one more level due to routes subdirectory
const PYTHON_SCRIPT = path.join(__dirname, '..', '..', 'analysis.py');

router.post('/encrypt', async (req, res) => {
    const { data, password } = req.body;
    
    const pythonProcess = spawn('python3', [
        PYTHON_SCRIPT,
        '--mode', 'encrypt',
        '--data', JSON.stringify(data),
        '--password', password
    ]);

    // Handle response...
    let result = '';
    
    pythonProcess.stdout.on('data', (data) => {
        result += data.toString();
    });

    pythonProcess.stderr.on('data', (data) => {
        console.error(`Error: ${data}`);
    });

    pythonProcess.on('close', (code) => {
        if (code !== 0) {
            return res.status(500).json({ error: 'Encryption failed' });
        }
        res.json(JSON.parse(result));
    });
});

module.exports = router; 