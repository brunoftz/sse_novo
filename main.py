from mitmproxy import http
from datetime import datetime
import re
import uuid
import urllib.parse
from urllib.parse import urlparse

from pymongo import MongoClient

MONGO_URI = "mongodb://127.0.0.1:27017"
MONGO_DB = "PI"
MONGO_COLLECTION = "indexacoes"

def mongo_log(msg):
    try:
        with open("/root/mongo_debug.log", "a", encoding="utf-8") as f:
            timestamp = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
            f.write(f"[{timestamp}] {msg}\n")
    except:
        pass
    
    
def fix_cors(flow: http.HTTPFlow):
    origin = flow.request.headers.get("Origin")
    if origin:
        flow.response.headers["Access-Control-Allow-Origin"] = origin
        flow.response.headers["Access-Control-Allow-Credentials"] = "true"
        flow.response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        flow.response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"

    # Se for preflight
    if flow.request.method.upper() == "OPTIONS":
        flow.response = http.Response.make(
            200,
            b"",
            flow.response.headers
        )

def get_mongo_collection():
    client = MongoClient(MONGO_URI)
    db = client[MONGO_DB]
    return db[MONGO_COLLECTION]

def extrair_dominio(url):
    try:
        parsed = urlparse(url)
        dominio = parsed.netloc.lower().replace("www.", "")
        return dominio
    except:
        return url


def get_url_motivo_from_db(url):
    try:
        mongo_log("Tentando conectar ao MongoDB...")
        collection = get_mongo_collection()

        # Testa conexão de verdade
        collection.database.command("ping")
        mongo_log("Conexão com MongoDB OK")

        dominio = extrair_dominio(url)
        mongo_log(f"URL recebida: {url}")
        mongo_log(f"Domínio extraído: {dominio}")

        resultado = collection.find_one({
            "$or": [
                {"urlWeb": {"$regex": dominio, "$options": "i"}},
                {"urlWeb": {"$regex": url, "$options": "i"}}
            ],
            "flag": True
        })

        mongo_log(f"Resultado Mongo: {resultado}")

        if resultado and "motivo" in resultado:
            mongo_log(f"Motivo encontrado: {resultado['motivo']}")
            
            # return resultado["motivo"]
            if resultado["motivo"] =="Gender":
                return "Gênero"
            elif resultado["motivo"] == "Race":
                return "Racial"
            else :
                return "X"
        


        mongo_log("Nenhum registro encontrado no Mongo")
        return None

    except Exception as e:
        mongo_log(f"ERRO MongoDB: {str(e)}")
        return None


# Regex para ignorar recursos estáticos (expandida)
STATIC_EXTENSIONS = re.compile(
    r".\.(css|js|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|otf|mp4|webm|avi|mp3|pdf|json|xml|webp|mpeg|ogg|wav|flac|mov|mkv|zip|rar|7z|tar|gz|exe|msi|apk|dmg|iso)(\?.)?$",
    re.IGNORECASE
)

# Regex para identificar URLs de rastreamento/análise
TRACKING_EXTENSIONS = re.compile(
    r".(google-analytics|googletagmanager|facebook\.net|hotjar|matomo|piwik|analytics|tracking|pixel|beacon|collect|stat).",
    re.IGNORECASE
)

# Carrega a blacklist
try:
    with open("/root/bloqueados.txt", "r", encoding="utf-8") as f:
        blacklist = [line.strip().lower() for line in f if line.strip()]
except FileNotFoundError:
    blacklist = []
    print("Arquivo bloqueados.txt não encontrado. Continuando sem blacklist.")

def request(flow: http.HTTPFlow) -> None:
    
    if "ssenovo-production.up.railway.app" in flow.request.pretty_url:
        return  # não intercepta SSE
    if flow.request.pretty_url.startswith("https://ssenovo-production.up.railway.app"):
        return  # não intercepta SSE
    try:
        url = flow.request.pretty_url.lower()

        # Força revalidação para navegações de documento.
        # Sem isso, F5 normal pode responder 304/cache e pular injeção/log.
        sec_fetch_dest = flow.request.headers.get("Sec-Fetch-Dest", "")
        sec_fetch_mode = flow.request.headers.get("Sec-Fetch-Mode", "")
        accept = flow.request.headers.get("Accept", "").lower()
        if (
            flow.request.method.lower() == "get"
            and sec_fetch_dest == "document"
            and sec_fetch_mode == "navigate"
            and "text/html" in accept
        ):
            flow.request.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
            flow.request.headers["Pragma"] = "no-cache"
            flow.request.headers["Expires"] = "0"
            flow.request.headers.pop("If-None-Match", None)
            flow.request.headers.pop("If-Modified-Since", None)
        
        
        # Verifica blacklist
        for item in blacklist:
            if item in url:
                encoded_url = urllib.parse.quote(url, safe='')
                motivo = get_url_motivo_from_db(url)
                if motivo:
                    print("Motivo encontrado:", motivo)

                redirect_url = f"http://192.168.12.1:5173/?site={encoded_url}&motivo={urllib.parse.quote(motivo) if motivo else 'X'}"
                flow.response = http.Response.make(
                    302,
                    b"",
                    {"Location": redirect_url}
                )

                return
                
        # Remove parâmetros de tracking comuns
        parsed = urllib.parse.urlparse(url)
        clean_url = urllib.parse.urlunparse(parsed._replace(query=""))
    except Exception as e:
        print(f"Erro ao processar request: {e}")

def response(flow: http.HTTPFlow) -> None:
    
    sec_fetch_dest = flow.request.headers.get("Sec-Fetch-Dest", "")
    sec_fetch_mode = flow.request.headers.get("Sec-Fetch-Mode", "")
    accept = flow.request.headers.get("Accept", "")

    # 🚫 ignora tudo que não for navegação real
    if sec_fetch_dest != "document":
        return

    if sec_fetch_mode != "navigate":
        return

    if "text/html" not in accept:
        return

    try:

        if "192.168.12.1:8001" in flow.request.pretty_url:
            return  # 🔥 NÃO TOCA NO SSE
        
        if "ssenovo-production.up.railway.app" in flow.request.pretty_url:
            return

        #fix_cors(flow)  # Corrige CORS para permitir comunicação com o frontend
        url = flow.request.pretty_url.lower()
        
        # Ignora recursos estáticos e de tracking
        if (STATIC_EXTENSIONS.match(url) or 
            TRACKING_EXTENSIONS.match(url) or
            flow.request.method.lower() != "get"):
            return
            
        # Remove espaços nos headers
        cleaned_headers = {k: v.strip() for k, v in flow.response.headers.items()}
        flow.response.headers.clear()
        flow.response.headers.update(cleaned_headers)
        # 🔥 REMOVE CSP (permite injeção de script)
        flow.response.headers.pop("content-security-policy", None)
        
        flow.response.headers.pop("content-security-policy-report-only", None)
        flow.response.headers.pop("x-content-security-policy", None)
        flow.response.headers.pop("x-webkit-csp", None)
        origin = flow.request.headers.get("Origin")
        if origin:
            flow.response.headers["Access-Control-Allow-Origin"] = origin
            flow.response.headers["Access-Control-Allow-Credentials"] = "true"
        
        # Registra apenas respostas bem-sucedidas (2xx)
        if 200 <= flow.response.status_code < 300:
            timestamp = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
            status_code = f"{flow.response.status_code:03d}"
            client_ip = flow.client_conn.address[0]
            nav_id = str(uuid.uuid4())
            
            # Tenta determinar o host principal
            host = flow.request.host.lower()
            log_line = f"{timestamp}:{status_code} {client_ip} {url} {nav_id}\n"
            
            # Verifica se é conteúdo HTML
            content_type = flow.response.headers.get("content-type", "").lower()
            
            # Tenta registrar no log principal
            try:
                if "text/html" in content_type:
                    #html_content = flow.response.get_text(strict=False).lower()
                    html = flow.response.get_text(strict=False)
                    html_lower = html.lower()
                    #if any(tag in html_content for tag in ["<html", "<title", "<body"]):
                    if any(tag in html_lower for tag in ["<html", "<title", "<body"]):
                        with open("/root/logs.txt", "a", encoding="utf-8") as f:
                            f.write(log_line)
                    
                        script = """
                        <script>

                        (function(){

                            let observer = null;
                            let frasesAtuais = [];
                            let intervaloRecheck = null;
                            
                            
                            // 🚫 NÃO roda em iframe
                            if (window !== window.top){
                                console.log("⛔ iframe detectado, ignorando");
                                return;
                            }

                            // 🚫 NÃO roda em navegação fake (SPA / fetch)
                            // const nav = performance.getEntriesByType("navigation")[0];
                            // if (!nav || nav.type !== "navigate") {
                            //     console.log("⛔ não é navegação real");
                            //     return;
                            // }

                            console.log("✅ Página principal detectada");

                            const __MITM_NAV_ID__ = "MITM_NAV_ID_PLACEHOLDER";

                            const style = document.createElement("style");
                            style.innerHTML = `
                            #overlay-root {
                                position: fixed;
                                inset: 0;
                                z-index: 2147483647;
                                pointer-events: none;
                            }

                            #overlay-blur {
                                position: absolute;
                                inset: 0;
                                backdrop-filter: blur(6px);
                                background: rgba(0,0,0,0.4);
                            }

                            #overlay-popup {
                                position: absolute;
                                top: 50%;
                                left: 50%;
                                transform: translate(-50%, -50%);
                                
                                background: white;
                                padding: 24px;
                                border-radius: 10px;

                                z-index: 2147483647;
                                pointer-events: auto;

                                box-shadow: 0 10px 40px rgba(0,0,0,0.3);
                                max-width: 400px;
                                text-align: center;
                                font-family: Arial;
                            }

                            .redacted {
                                display: inline-block;
                                background: #eceff3;
                                color: #3b4350;
                                padding: 2px 10px;
                                border-radius: 999px;
                                border: 1px solid #d7dde6;
                                font-weight: 600;
                                line-height: 1.25;
                            }
                            `;
                            document.head.appendChild(style);

                            console.log("🔌 Iniciando conexão com SSE...");

                            function gerarId() {
                                return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
                                    const r = Math.random() * 16 | 0;
                                    const v = c === 'x' ? r : (r & 0x3 | 0x8);
                                    return v.toString(16);
                                });
                            }

                            // 🔑 clientId (persistente)
                            let clientId = localStorage.getItem("clientId");
                            if (!clientId) {
                                clientId = (crypto.randomUUID && crypto.randomUUID()) || gerarId();
                                localStorage.setItem("clientId", clientId);
                                console.log("🆕 Novo clientId criado");
                            }

                            // 🔑 tabId (por aba)
                            let tabId = sessionStorage.getItem("tabId");
                            if (!tabId) {
                                tabId = (crypto.randomUUID && crypto.randomUUID()) || gerarId();
                                sessionStorage.setItem("tabId", tabId);
                                console.log("🆕 Novo tabId criado");
                            }

                            console.log("🆔 clientId:", clientId);
                            console.log("🧩 tabId:", tabId);
                            
                            // VERIFY_GATE_START (remova este bloco para desativar gate)
                            function createVerifyGate() {
                                if (document.getElementById("verify-gate-overlay")) return;
                                if (document.body) {
                                    document.body.style.visibility = "hidden";
                                }
                                const gate = document.createElement("div");
                                gate.id = "verify-gate-overlay";
                                gate.style.position = "fixed";
                                gate.style.inset = "0";
                                gate.style.background = "#0f172a";
                                gate.style.color = "#fff";
                                gate.style.zIndex = "2147483646";
                                gate.style.display = "flex";
                                gate.style.alignItems = "center";
                                gate.style.justifyContent = "center";
                                gate.style.fontFamily = "Arial, sans-serif";
                                gate.innerHTML = '<div style="text-align:center;"><h3 style="margin:0 0 8px 0;">Verificando conteúdo...</h3><p style="margin:0;">Aguarde alguns instantes.</p></div>';
                                document.documentElement.appendChild(gate);
                            }
                            function releaseVerifyGate() {
                                const gate = document.getElementById("verify-gate-overlay");
                                if (gate) gate.remove();
                                if (document.body) {
                                    document.body.style.visibility = "visible";
                                }
                            }
                            createVerifyGate();
                            // VERIFY_GATE_END

                            // 🚀 evita múltiplas conexões
                            if (window.__SSE_CONNECTED__) {
                                console.log("⚠️ SSE já conectado");
                                return;
                            }
                            window.__SSE_CONNECTED__ = true;

                            // 🚀 conecta no SSE
                            const url = `https://ssenovo-production.up.railway.app/stream?clientId=${encodeURIComponent(clientId)}&tabId=${encodeURIComponent(tabId)}&navId=${encodeURIComponent(__MITM_NAV_ID__)}`;
                            const evtSource = new EventSource(url);

                            evtSource.onopen = function () {
                                console.log("✅ Conectado ao SSE com sucesso!");
                            };

                            evtSource.onmessage = function (event) {

                                console.log("📩 Evento bruto recebido:", event.data);

                                if (!event.data || event.data.trim() === "") {
                                    console.log("💓 Heartbeat recebido (keep-alive)");
                                    return;
                                }

                                try {
                                    const data = JSON.parse(event.data);

                                    console.log("📦 JSON parseado:", data);

                                    if (data.type === "highlight") {
                                        console.log("🚨 Highlight acionado com frases:", data.texts);

                                        iniciarObservador(data.texts);
                                        console.log("🔥 chamando popup...");
                                        aplicarBlurPopup(data.motivos || []);
                                        // VERIFY_GATE_RELEASE
                                        releaseVerifyGate();
                                    }

                                    if (data.type === "verification_done") {
                                        console.log("✅ Verificação concluída.");
                                        // VERIFY_GATE_RELEASE
                                        releaseVerifyGate();
                                    }

                                } catch (err) {
                                    console.error("❌ Erro ao fazer parse do JSON:", err);
                                }
                            };

                            evtSource.onerror = function (err) {
                                console.error("❌ Erro na conexão SSE:", err);

                                if (evtSource.readyState === EventSource.CLOSED) {
                                    console.error("🔴 Conexão SSE foi fechada");
                                } else if (evtSource.readyState === EventSource.CONNECTING) {
                                    console.warn("🟡 Tentando reconectar ao SSE...");
                                }
                            };


                            function observarERebloquear(frases) {

                                const observer = new MutationObserver(() => {
                                    bloquearMultiplasFrases(frases);
                                });

                                observer.observe(document.body, {
                                    childList: true,
                                    subtree: true
                                });

                                // para depois de um tempo (evita loop infinito)
                                setTimeout(() => {
                                    observer.disconnect();
                                    console.log("🛑 observer desligado");
                                }, 5000);
                            }
                            function bloquearMultiplasFrases(frases) {

                                console.log("🔍 Iniciando bloqueio de frases...");

                                const root = document.getElementById("conteudo");
                                const target = root ? root : document.body;

                                if (!root) {
                                    console.warn("⚠️ #conteudo não encontrado, usando document.body");
                                }

                                target.classList.add("blurred");

                                function removerLink(anchorEl) {
                                    if (!anchorEl || !anchorEl.parentNode) return;
                                    const parent = anchorEl.parentNode;
                                    while (anchorEl.firstChild) {
                                        parent.insertBefore(anchorEl.firstChild, anchorEl);
                                    }
                                    parent.removeChild(anchorEl);
                                }

                                frases.forEach(frase => {

                                    console.log("➡️ Procurando frase:", frase);

                                    const walker = document.createTreeWalker(
                                        target,
                                        NodeFilter.SHOW_TEXT,
                                        null,
                                        false
                                    );

                                    let node;

                                    while (node = walker.nextNode()) {

                                        const texto = node.nodeValue;

                                        if (texto.includes(frase)) {

                                            console.log("🚫 Frase encontrada:", frase);
                                            const anchor = node.parentElement?.closest ? node.parentElement.closest("a") : null;

                                            const partes = texto.split(frase);
                                            const fragment = document.createDocumentFragment();

                                            partes.forEach((parte, index) => {

                                                fragment.appendChild(
                                                    document.createTextNode(parte)
                                                );

                                                if (index < partes.length - 1) {

                                                    const span = document.createElement("span");
                                                    span.className = "redacted";
                                                    span.textContent = "[redacted]";

                                                    fragment.appendChild(span);
                                                }
                                            });

                                            node.parentNode.replaceChild(fragment, node);

                                            if (anchor) {
                                                console.log("🔗 Link removido por conter frase censurada");
                                                removerLink(anchor);
                                            }
                                        }
                                    }
                                });

                                console.log("✅ Bloqueio concluído");
                            }

                            function traduzirMotivo(motivo) {
                                const m = String(motivo || "").toLowerCase();
                                if (m === "gender") return "Genero";
                                if (m === "race") return "Racial";
                                if (m === "religion") return "Religiao";
                                if (m === "lgbtqphobia") return "LGBTQfobia";
                                if (m === "xenophobia") return "Xenofobia";
                                return motivo || "Nao informado";
                            }
                            
                            function getSiteUrlForQr() {
                                const params = new URLSearchParams(window.location.search);
                                const rawSite = params.get("site");
                                if (rawSite) {
                                    try {
                                        return decodeURIComponent(rawSite);
                                    } catch (e) {
                                        return rawSite;
                                    }
                                }
                                return window.location.href;
                            }

                            function aplicarBlurPopup(motivos) {

                                console.log("🌀 Aplicando blur + popup");

                                if (document.getElementById("overlay-root")) return;

                                const root = document.createElement("div");
                                root.id = "overlay-root";

                                const blur = document.createElement("div");
                                blur.id = "overlay-blur";

                                const popup = document.createElement("div");
                                popup.id = "overlay-popup";

                                const motivosValidos = Array.isArray(motivos)
                                    ? motivos.filter(Boolean)
                                    : [];
                                const siteUrl = getSiteUrlForQr();
                                const qrCodeUrl = `https://api.qrserver.com/v1/create-qr-code/?size=250x250&data=${encodeURIComponent(siteUrl)}`;

                                const motivoHtml = motivosValidos.length
                                    ? `<p><strong>Motivos detectados:</strong> ${motivosValidos.map(traduzirMotivo).join(", ")}</p>`
                                    : `<p><strong>Motivo detectado:</strong> Nao informado</p>`;

                                popup.innerHTML = `
                                    <h2>Conteudo bloqueado</h2>
                                    <div style="display:flex; gap:16px; align-items:center; text-align:left; margin-top:12px;">
                                        <div style="flex:0 0 170px; display:flex; flex-direction:column; align-items:center; gap:8px;">
                                            <p style="font-size:13px; margin:0; text-align:center;">
                                                Leia o <strong>QR Code</strong> em nosso aplicativo para sugerir desbloqueio.
                                            </p>
                                            <img
                                                src="${qrCodeUrl}"
                                                alt="QR Code do site"
                                                style="width:160px; height:160px; border:1px solid #ddd; border-radius:8px;"
                                            />
                                        </div>
                                        <div style="flex:1; min-width:0;">
                                            <p>Algumas frases foram ocultadas automaticamente.</p>
                                            ${motivoHtml}
                                            <p style="word-break:break-all; font-size:12px;"><strong>Site:</strong> ${siteUrl}</p>
                                        </div>
                                    </div>
                                    <button id="fechar">Entendi</button>
                                `;

                                root.appendChild(blur);
                                root.appendChild(popup);
                                document.documentElement.appendChild(root);

                                document.getElementById("fechar").onclick = () => {
                                    console.log("🟢 Usuário fechou o popup");
                                    root.remove();
                                };
                            }
                            
                            function iniciarObservador(frases) {

                                frasesAtuais = frases;

                                if (observer) observer.disconnect();

                                const target = document.body;

                                observer = new MutationObserver(() => {
                                    bloquearMultiplasFrases(frasesAtuais);
                                });

                                observer.observe(target, {
                                    childList: true,
                                    subtree: true
                                });

                                console.log("👀 Observer iniciado (modo contínuo)");

                                // 🔥 RECHECK FORÇADO (IMPORTANTE PRA SPA)
                                if (intervaloRecheck) clearInterval(intervaloRecheck);

                                intervaloRecheck = setInterval(() => {
                                    console.log("🔁 Rechecando DOM...");
                                    bloquearMultiplasFrases(frasesAtuais);
                                }, 1000); // a cada 1s

                                // 🛑 PARA depois de 10 segundos (ajusta se quiser)
                                setTimeout(() => {
                                    if (observer) observer.disconnect();
                                    if (intervaloRecheck) clearInterval(intervaloRecheck);
                                    console.log("🛑 Observer finalizado (timeout)");
                                }, 10000);
                            }

                        })();
                        </script>

                        """
                        script = script.replace("MITM_NAV_ID_PLACEHOLDER", nav_id)
                        if "</body>" in html:
                            html = html.replace("</body>", script + "</body>")
                        else:
                            html += script
                            
                        flow.response.set_text(html)
                        
        
                
                # Se não for HTML ou não tiver tags HTML, registra no light_log
                with open("/root/light_logs.txt", "a", encoding="utf-8") as f:
                    f.write(log_line)
                    
            except UnicodeDecodeError:
                # Conteúdo binário ou encoding inválido
                with open("/root/light_logs.txt", "a", encoding="utf-8") as f:
                    f.write(log_line)
                    
            except Exception as e:
                print(f"Erro ao processar resposta: {e}")
                with open("/root/light_logs.txt", "a", encoding="utf-8") as f:
                    f.write(log_line)
                    
    except Exception as e:
        print(f"Erro geral no handler de resposta: {e}")
        # Tenta registrar pelo menos a URL básica
        try:
            timestamp = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
            client_ip = flow.client_conn.address[0] if flow.client_conn else "0.0.0.0"
            with open("/root/light_logs.txt", "a", encoding="utf-8") as f:
                f.write(f"{timestamp}:ERR {client_ip} {url}\n")
        except:
            pass
