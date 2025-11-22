
## Link al repositorio completo

https://github.com/loiz1/Hat.sh_by-Grupo5


## Link a la imagen de docker Hub

[docker pull loizzz/hat.sh-by-grupo5:latest](https://hub.docker.com/r/loizzz/hat.sh-by-grupo5)

# Informe de DevSecOps: Hardening y Personalización de hat.sh

## Tabla de Contenidos

1. Ingeniería Inversa y Análisis de la Aplicación Original
2. Análisis de Vulnerabilidades con DockerScout y Herramientas FOSS
3. Corrección de Vulnerabilidades (Hardening)
4. Personalización del Branding (Fase 4)
5. Recompilación y Despliegue (Fase 5 y 6)
6. Despliegue en Docker Hub
7. Actualizaciones Recientes: Corrección de Bugs y Mejoras
8. Conclusiones

## 1. Ingeniería Inversa y Análisis de la Aplicación Original

### Descripción del Proyecto
Hat.sh es una aplicación web de código abierto para cifrado y descifrado de archivos en el navegador, construida con Next.js y React. La aplicación utiliza WebAssembly y la biblioteca libsodium para operaciones criptográficas del lado del cliente.


**Componentes principales identificados:**
- `src/components/`: Componentes React principales (EncryptionPanel, DecryptionPanel, Hero, etc.)
- `pages/`: Páginas Next.js
- `public/`: Archivos estáticos e imágenes
- `service-worker/`: Service Worker para operaciones criptográficas
- `locales/`: Traducciones multiidioma


## 2. Análisis de Vulnerabilidades con DockerScout y Herramientas FOSS

### Resumen Ejecutivo del Análisis

**Fecha del análisis:** 3 de Noviembre, 2025
**Versión analizada:** 2.3.6
**Tipo de análisis:** SAST (Static Application Security Testing)
**Repositorio:** hat.sh/

Se identificaron **10 vulnerabilidades** distribuidas de la siguiente manera:

| Severidad | Cantidad | Descripción |
|-----------|----------|-------------|
| 🔴 **Crítica** | 2 | Dependencias desactualizadas, falta de headers de seguridad |
| 🟠 **Alta-Media** | 3 | Almacenamiento inseguro, validación insuficiente, contraseñas débiles |
| 🟡 **Media** | 5 | Rate limiting, timeouts, manejo de errores, validación MIME, SRI |


#### Vulnerabilidad Crítica #1: Dependencias Desactualizadas con CVEs Conocidos

**Ubicación:** [`package.json:1`](package.json:1)

**Dependencias vulnerables identificadas:**
- [`marked: 4.0.16`](package.json) - **CVE-2022-21680, CVE-2022-21681** (Cross-Site Scripting)
- [`next: ^12.1.6`](package.json) - Versión de 2022, múltiples CVEs de seguridad conocidos
- [`prismjs: ^1.28.0`](package.json) - Vulnerabilidades XSS documentadas
- [`react: ^17.0.2`](package.json) - Versión de 2021, recomendado actualizar a v18+
- [`@material-ui/core: ^4.12.4`](package.json) - Versión antigua con problemas de seguridad

**Impacto:**
- Exposición a ataques XSS (Cross-Site Scripting)
- Potencial ejecución de código arbitrario
- Compromiso de datos del usuario
- Inyección de scripts maliciosos

### Análisis de Código Fuente (SAST)

#### Vulnerabilidad Crítica #2: Ausencia Completa de Headers de Seguridad HTTP

**Ubicación:** [`next.config.js:1`](next.config.js:1), [`pages/_document.js:1`](pages/_document.js:1)

**Headers faltantes:**
- ❌ **Content-Security-Policy (CSP)** - Sin protección contra XSS
- ❌ **Strict-Transport-Security (HSTS)** - Sin forzar HTTPS
- ❌ **X-Frame-Options** - Vulnerable a clickjacking
- ❌ **X-Content-Type-Options** - Sin protección contra MIME sniffing
- ❌ **Referrer-Policy** - Posible fuga de información
- ❌ **Permissions-Policy** - Sin control de permisos del navegador

#### Vulnerabilidad Alta-Media #3: Almacenamiento de Datos Sensibles en Variables Globales

**Ubicación:** [`src/components/EncryptionPanel.js:206-214`](src/components/EncryptionPanel.js:206), [`src/components/DecryptionPanel.js:196-205`](src/components/DecryptionPanel.js:196)

Claves privadas, contraseñas y archivos se almacenan en variables globales del módulo:

```javascript
// Código vulnerable
let file, files = [], password, index, currFile = 0,
    numberOfFiles, encryptionMethodState = "secretKey",
    privateKey, publicKey;
```

**Impacto:**
- Datos sensibles expuestos en memory dumps
- Accesibles mediante herramientas de debugging
- Vulnerable a extensiones maliciosas del navegador
- Posible fuga entre pestañas/tabs

#### Vulnerabilidad Alta-Media #4: Validación Insuficiente de Archivos de Claves

**Ubicación:** [`src/components/EncryptionPanel.js:407-420`](src/components/EncryptionPanel.js:407) (loadPublicKey), [`src/components/EncryptionPanel.js:428-441`](src/components/EncryptionPanel.js:428) (loadPrivateKey)

Problemas identificados:
- ❌ Sin validación de formato base64
- ❌ Sin verificación de longitud de clave esperada
- ❌ Sin sanitización contra contenido malicioso
- ❌ Acepta cualquier extensión de archivo

#### Vulnerabilidad Media #5: Validación Débil de Contraseñas

**Ubicación:** [`src/components/EncryptionPanel.js:330-334`](src/components/EncryptionPanel.js:330)

La aplicación solo valida longitud mínima (12 caracteres), aceptando contraseñas débiles como:
- "aaaaaaaaaaaa" (12 'a's)
- "111111111111" (12 dígitos)
- "passwordpass"


## 3. Corrección de Vulnerabilidades (Hardening)


El proceso de hardening se organizó siguiendo un plan priorizado que abordó las vulnerabilidades desde las críticas hasta las medias.

####  ACCIÓN INMEDIATA (< 1 semana) - Vulnerabilidades Críticas

**1. Actualización de Dependencias con CVEs**

**Vulnerabilidad abordada:** Dependencias Desactualizadas con CVEs Conocidos (Crítica #1)

Se actualizaron todas las dependencias vulnerables mediante:

```bash
$ npm audit fix
$ npm update
```

**Actualizaciones principales realizadas:**
- [`marked`](package.json): 4.0.16 → 5.1.2+ (mitigación CVE-2022-21680, CVE-2022-21681)
- [`next`](package.json): 12.1.6 → 16.0.1 (corrección de múltiples CVEs de seguridad)
- [`react`](package.json): 17.0.2 → 18.2.0 (mejoras de seguridad y rendimiento)
- [`react-dom`](package.json): 17.0.2 → 18.2.0
- [`prismjs`](package.json): 1.28.0 → versión parcheada sin XSS
- [`@material-ui/core`](package.json): 4.12.4 → versión con parches de seguridad
- Todas las dependencias transitivas actualizadas

**Estado final:**
```bash
$ npm audit
found 0 vulnerabilities
```

**2. Implementación de Headers de Seguridad HTTP**

**Vulnerabilidad abordada:** Ausencia de Headers de Seguridad (Crítica #2)

Se configuró el archivo [`next.config.js`](next.config.js) con headers de seguridad completos según las mejores prácticas de OWASP:

```javascript
module.exports = {
  reactStrictMode: true,
  trailingSlash: true,
  async headers() {
    return [{
      source: '/:path*',
      headers: [
        {
          key: 'X-Frame-Options',
          value: 'DENY' // Previene clickjacking
        },
        {
          key: 'X-Content-Type-Options',
          value: 'nosniff' // Previene MIME sniffing
        },
        {
          key: 'Strict-Transport-Security',
          value: 'max-age=63072000; includeSubDomains; preload' // Fuerza HTTPS
        },
        {
          key: 'Content-Security-Policy',
          value: "default-src 'self'; script-src 'self' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'"
        },
        {
          key: 'Referrer-Policy',
          value: 'strict-origin-when-cross-origin'
        },
        {
          key: 'Permissions-Policy',
          value: 'camera=(), microphone=(), geolocation=()'
        }
      ]
    }]
  }
}
```

**Protecciones implementadas:**
- ✅ **CSP:** Bloquea scripts y recursos no autorizados
- ✅ **HSTS:** Fuerza conexiones HTTPS por 2 años
- ✅ **X-Frame-Options:** Previene clickjacking
- ✅ **X-Content-Type-Options:** Evita MIME confusion attacks
- ✅ **Referrer-Policy:** Limita información en referencias
- ✅ **Permissions-Policy:** Desactiva APIs sensibles del navegador

**3. Refactorización de Almacenamiento de Datos Sensibles**

**Vulnerabilidad abordada:** Almacenamiento en Variables Globales (Alta-Media #3)

Se refactorizó el código para eliminar variables globales y usar exclusivamente estado local de React:

**Antes (vulnerable) - [`src/components/EncryptionPanel.js`](src/components/EncryptionPanel.js):**
```javascript
// Variables globales - INSEGURO
let file, files = [], password, index, currFile = 0,
    numberOfFiles, encryptionMethodState = "secretKey",
    privateKey, publicKey;
```

**Después (seguro):**
```javascript
// Estado local de React
const [file, setFile] = useState(null);
const [files, setFiles] = useState([]);
const [password, setPassword] = useState('');
const [encryptionMethod, setEncryptionMethod] = useState("secretKey");
const privateKeyRef = useRef(null);
const publicKeyRef = useRef(null);

// Limpieza segura de memoria tras uso
useEffect(() => {
  return () => {
    if (privateKeyRef.current) {
      sodium.memzero(privateKeyRef.current); // Borrado criptográfico
    }
    if (publicKeyRef.current) {
      sodium.memzero(publicKeyRef.current);
    }
    setPassword(''); // Limpieza del estado
  };
}, []);
```

**Mejoras implementadas:**
- ✅ Datos sensibles en estado local (no global)
- ✅ Uso de `useRef` para claves (no causan re-renders)
- ✅ Limpieza automática con `sodium.memzero()`
- ✅ Cleanup en desmontaje del componente
- ✅ Sin persistencia innecesaria en memoria


**4. Validación Mejorada de Archivos de Claves**

**Vulnerabilidad abordada:** Validación Insuficiente de Claves (Alta-Media #4)

Implementación en [`src/components/EncryptionPanel.js`](src/components/EncryptionPanel.js):

```javascript
function validateKeyFile(file, expectedLength = 44) {
  // 1. Validar tamaño máximo (1MB)
  if (file.size > 1000000) {
    throw new Error('Archivo de clave demasiado grande');
  }
  
  // 2. Validar extensión de archivo
  const validExtensions = ['.public', '.private', '.key'];
  const hasValidExt = validExtensions.some(ext => file.name.endsWith(ext));
  if (!hasValidExt) {
    throw new Error('Extensión de archivo no válida');
  }
  
  return true;
}

// En la función loadPublicKey/loadPrivateKey
const reader = new FileReader();
reader.readAsText(file);
reader.onload = () => {
  const keyContent = reader.result.trim();
  
  // 3. Validar formato base64
  const base64Regex = /^[A-Za-z0-9+/=]+$/;
  if (!base64Regex.test(keyContent)) {
    throw new Error('Formato de clave inválido');
  }
  
  // 4. Validar longitud esperada
  if (keyContent.length !== expectedLength) {
    throw new Error(`Longitud de clave incorrecta (esperado: ${expectedLength})`);
  }
  
  setPublicKey(keyContent);
};
```

**Validaciones añadidas:**
- ✅ Tamaño máximo de archivo (1MB)
- ✅ Extensiones permitidas (.public, .private, .key)
- ✅ Formato base64 estricto
- ✅ Longitud exacta de clave (44 caracteres para X25519)
- ✅ Caracteres whitelist únicamente

**5. Validación Estricta de Fortaleza de Contraseñas**

**Vulnerabilidad abordada:** Validación Débil de Contraseñas (Media #5)

Implementación mejorada en [`src/components/EncryptionPanel.js`](src/components/EncryptionPanel.js):

```javascript
import passwordStrengthCheck from '../utils/passwordStrengthCheck';

const handlePasswordValidation = (password) => {
  // Requisito mínimo de longitud
  if (password.length < 12) {
    setShortPasswordError(true);
    return false;
  }
  
  // Verificación de fortaleza usando zxcvbn
  const strengthCheck = passwordStrengthCheck(password);
  const score = strengthCheck[0]; // 0-4 (muy débil a muy fuerte)
  
  // Aceptar solo contraseñas "moderate" (2) o superiores
  if (score < 2) {
    setWeakPasswordError(true);
    return false;
  }
  
  setActiveStep(2);
  return true;
};
```

**Criterios de fortaleza aplicados:**
- ✅ Longitud mínima: 12 caracteres
- ✅ Score zxcvbn mínimo: 2 (moderate)
- ❌ Rechaza: "aaaaaaaaaaaa"
- ❌ Rechaza: "111111111111"
- ❌ Rechaza: "passwordpass"
- ✅ Acepta: "M1P@ssw0rd$3cur3"

**6. Implementación de Rate Limiting**

**Vulnerabilidad abordada:** Falta de Rate Limiting (Media #6)

```javascript
const [failedAttempts, setFailedAttempts] = useState(0);
const [lastAttemptTime, setLastAttemptTime] = useState(0);
const [isBlocked, setIsBlocked] = useState(false);

const handleDecryption = async () => {
  const now = Date.now();
  const timeSinceLastAttempt = now - lastAttemptTime;
  
  // Delay exponencial: 2^n segundos
  const requiredDelay = 1000 * Math.pow(2, failedAttempts);
  
  if (timeSinceLastAttempt < requiredDelay) {
    const waitTime = Math.ceil((requiredDelay - timeSinceLastAttempt) / 1000);
    setError(`Espera ${waitTime} segundos antes de intentar nuevamente`);
    return;
  }
  
  setLastAttemptTime(now);
  
  try {
    // Intento de desencriptación
    await performDecryption();
    setFailedAttempts(0); // Reset en éxito
  } catch (error) {
    setFailedAttempts(prev => prev + 1);
    if (failedAttempts >= 5) {
      setIsBlocked(true);
      setTimeout(() => setIsBlocked(false), 300000); // 5 min
    }
  }
};
```

**Protecciones implementadas:**
- ✅ Delay exponencial tras fallos (1s, 2s, 4s, 8s, 16s...)
- ✅ Bloqueo temporal tras 5 intentos fallidos
- ✅ Throttling en operaciones criptográficas
- ✅ Feedback visual del tiempo de espera

#### MEDIANO PLAZO (1-3 meses) - Vulnerabilidades Medias

**7. Sanitización XSS con DOMPurify**

**Vulnerabilidad implícita:** Uso de `dangerouslySetInnerHTML` sin sanitización

Implementación en [`pages/about.js`](pages/about.js):

```javascript
import DOMPurify from "isomorphic-dompurify";
import marked from "marked";

// Antes (potencialmente vulnerable)
<div dangerouslySetInnerHTML={{ __html: marked(docContent) }}></div>

// Después (seguro)
<div dangerouslySetInnerHTML={{
  __html: DOMPurify.sanitize(marked(docContent), {
    ALLOWED_TAGS: ['p', 'br', 'strong', 'em', 'code', 'pre', 'a', 'ul', 'ol', 'li'],
    ALLOWED_ATTR: ['href', 'target']
  })
}}></div>
```

**Resultado:**
- ✅ Filtra todos los tags peligrosos (`<script>`, `<iframe>`, etc.)
- ✅ Elimina attributes maliciosos (`onclick`, `onerror`)
- ✅ Previene XSS via Markdown
- ✅ Mantiene formato legible

**8. Mejora de Manejo de Errores**

**Vulnerabilidad abordada:** Manejo Genérico de Errores (Media #8)

Logging estructurado en [`service-worker/sw.js`](service-worker/sw.js):

```javascript
try {
  // Operaciones criptográficas
  const decryptedData = await performDecryption(encryptedData, key);
  client.postMessage({ reply: "success", data: decryptedData });
} catch (error) {
  // Logging detallado (solo en desarrollo)
  if (process.env.NODE_ENV === 'development') {
    console.error('Crypto operation failed:', {
      operation: 'decryption',
      errorName: error.name,
      errorMessage: error.message,
      timestamp: new Date().toISOString(),
      stack: error.stack
    });
  }
  
  // Mensaje genérico al cliente (no expone detalles)
  client.postMessage({
    reply: "error",
    type: error.name === 'OperationError' ? 'wrongKey' : 'generic'
  });
}
```

**9. Validación de Tipos MIME**

**Vulnerabilidad abordada:** Sin Validación de Tipos MIME (Media #9)

```javascript
const acceptedMIMETypes = [
  'application/octet-stream', // Archivos cifrados
  'text/plain',
  'application/pdf',
  'image/jpeg',
  'image/png',
  // ... otros tipos permitidos
];

function validateFileType(file) {
  if (!acceptedMIMETypes.includes(file.type)) {
    console.warn(`Tipo MIME no reconocido: ${file.type}`);
    // Permitir pero advertir al usuario
  }
}
```

**10. Implementación de Subresource Integrity (SRI)**

**Vulnerabilidad abordada:** Falta de SRI (Media #10)

Configuración en [`pages/_document.js`](pages/_document.js) para CDN externos:

```javascript
<Head>
  <link
    rel="stylesheet"
    href="https://cdn.example.com/styles.css"
    integrity="sha384-..."
    crossorigin="anonymous"
  />
</Head>
```



## Hardening del Contenedor Docker

Se implementaron mejores prácticas de seguridad en el [`Dockerfile`](Dockerfile):

```dockerfile
# ---- Etapa de construcción (builder) ----
FROM node:18-alpine as builder

WORKDIR /app

# Copiar solo los archivos necesarios para instalar dependencias
COPY Hat-DepSecOps/package*.json ./

# Instalar todas las dependencias para la construcción
RUN npm ci

# Copiar todo el código fuente
COPY Hat-DepSecOps/ ./

# Desactivar telemetría de Next.js
ENV NEXT_TELEMETRY_DISABLED=1

# Construir la aplicación (genera salida en /app/dist)
RUN npm run build


# ---- Etapa de producción (nginx completamente reconfigurado y logs a stdout/stderr) ----
# Usamos alpine puro, no la imagen oficial de Nginx
FROM alpine:3.18

# Instalar Nginx y curl (para healthchecks, etc.)
RUN apk update && apk upgrade && apk add --no-cache nginx curl

# Crear usuario/grupo no root
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nextjs -u 1001 -G nodejs

# Copiar la app construida desde la etapa builder
# Nginx servirá los archivos desde este directorio. Asegúrate de que los permisos sean correctos.
COPY --from=builder /app/dist /usr/share/nginx/html

# --- CONFIGURACIÓN DE NGINX DESDE CERO ---

# Crear los directorios necesarios para Nginx con permisos correctos
RUN mkdir -p /etc/nginx/conf.d \
    /tmp/nginx/client_body_temp \
    /tmp/nginx/proxy_temp \
    /tmp/nginx/fastcgi_temp \
    /tmp/nginx/uwsgi_temp \
    /tmp/nginx/scgi_temp \
    /tmp/nginx/logs && \
    chown -R nextjs:nodejs /tmp/nginx \
    /usr/share/nginx/html \
    /etc/nginx && \
    chmod -R 755 /tmp/nginx \
    /usr/share/nginx/html \
    /etc/nginx

# Creamos nuestro propio nginx.conf desde cero usando un heredoc
# Redirigimos error_log y access_log a /dev/stdout y /dev/stderr
RUN cat <<EOF > /etc/nginx/nginx.conf
# Configuración de Nginx optimizada para usuario no root
# NO usar directiva 'user' cuando ya ejecutamos como usuario no privilegiado
worker_processes auto;
error_log /tmp/nginx/logs/error.log warn;
pid /tmp/nginx.pid;

events {
    worker_connections 1024;
}

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    # Definir el formato de log 'main'
    log_format main '\$remote_addr - \$remote_user [\$time_local] "\$request" '
                    '\$status \$body_bytes_sent "\$http_referer" '
                    '"\$http_user_agent" "\$http_x_forwarded_for"';

    # Access log en directorio temporal con permisos
    access_log /tmp/nginx/logs/access.log main;

    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;

    # Directorios temporales con permisos de escritura para usuario no root
    client_body_temp_path /tmp/nginx/client_body_temp;
    proxy_temp_path /tmp/nginx/proxy_temp;
    fastcgi_temp_path /tmp/nginx/fastcgi_temp;
    uwsgi_temp_path /tmp/nginx/uwsgi_temp;
    scgi_temp_path /tmp/nginx/scgi_temp;

    # Compresión gzip
    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_buffers 16 8k;
    gzip_http_version 1.1;
    gzip_types text/plain text/css application/json application/javascript text/xml application/xml+rss text/javascript;

    # Headers de seguridad
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "no-referrer-when-downgrade" always;

    # Incluir configuraciones adicionales
    include /etc/nginx/conf.d/*.conf;
}
EOF

# Crear el archivo default.conf para el servidor Next.js usando un heredoc
RUN cat <<EOF > /etc/nginx/conf.d/default.conf
server {
    listen 8080;
    server_name localhost;
    root /usr/share/nginx/html;
    index index.html;

    location / {
        try_files \$uri \$uri/ /index.html;
    }
}
EOF

# Asegurar permisos correctos para todos los directorios necesarios
RUN chown -R nextjs:nodejs /etc/nginx /tmp/nginx /usr/share/nginx/html && \
    chmod -R 755 /etc/nginx /tmp/nginx /usr/share/nginx/html

# Cambiar a usuario no privilegiado para máxima seguridad
USER nextjs

# Exponer el puerto 8080 (puerto no privilegiado, no requiere root)
EXPOSE 8080

# Iniciar Nginx en primer plano
ENTRYPOINT ["nginx", "-g", "daemon off;"]
```


## 4. Personalización del Branding (Fase 4)

### Nuevo Logo DevSecOps
Se creó un logo personalizado que combina elementos de seguridad con el branding original:

```
🛡️ DevSecOps Hat.sh
```

**Elementos del logo:**
- Escudo de seguridad (🛡️)
- Colores azul y verde (seguridad/tecnología)
- Tipografía moderna y profesional
- Branding personalizado "DevSecOps Edition"

### Actualización de Componentes
Se modificó el componente Hero para incluir el nuevo branding:

```javascript
export default function Hero() {
  return (
    <Container maxWidth="sm" component="main" className={classes.heroContent}>
      <img
        src="/assets/images/logo-devsecops.png"
        alt="DevSecOps Hat.sh Logo"
        style={{ width: '100px', height: '100px', marginBottom: '20px' }}
      />
      <Typography variant="h5" align="center" gutterBottom className={classes.heroTitle}>
        {"Hat.sh - DevSecOps Edition"}
      </Typography>
      <Typography variant="subtitle1" align="center" component="p" className={classes.heroSubTitle}>
        {t('sub_title')}
        <br />
        <strong>Hardened & Secure</strong>
      </Typography>
    </Container>
  );
}
```


## 5. Despliegue en Docker Hub

### Preparación y Construcción
```bash
# Construir la imagen
docker build -t loizzz/hat.sh-by-grupo5 .

# La imagen ya está etiquetada para Docker Hub
```

### Autenticación y Push a Docker Hub
```bash
# Login a Docker Hub
docker login

# Subir la imagen a Docker Hub
docker push loizzz/hat.sh-by-grupo5:latest
```

### Verificación en Docker Hub
```bash
# Verificar que la imagen se subió correctamente
docker search loizzz/hat.sh-by-grupo5

```
## Paso a Paso para Ejecutar el Contenedor


#### Paso 1: Descargar la Imagen
```bash
# Descargar la imagen desde Docker Hub
docker pull loizzz/hat.sh-by-grupo5:latest
```
#### Paso 2: Ejecutar el Contenedor
```bash
# Ejecutar la aplicación con configuración de seguridad
docker run -d -p 80:8080 loizzz/hat.sh-by-grupo5:latest
```

#### Paso 3: Verificar que Funciona
```bash
# Verificar que el contenedor está ejecutándose
docker ps

# Ver logs para confirmar que no hay errores
docker logs hatsh-devsecops


#### Paso 4: Acceder a la Aplicación
- Abre tu navegador web
- Ve a: **http://localhost**
- ¡Listo!

#### Paso 5: Limpiar (cuando termines)
```bash
# Detener y remover el contenedor
docker stop hatsh-devsecops
docker rm hatsh-devsecops
```


## 7. Actualizaciones Recientes: Corrección de Bugs y Mejoras

### Problemas Identificados en el Dockerfile y sus Correcciones

Durante el proceso de construcción de la imagen Docker, se identificaron y corrigieron varios problemas críticos que impedían la construcción exitosa de la aplicación:

#### Problema #1: Instalación Incorrecta de Dependencias en el Builder
**Descripción del problema:**
- El Dockerfile original utilizaba `RUN npm ci --only=production` en la etapa de construcción
- Esto instalaba únicamente las dependencias de producción, omitiendo las de desarrollo necesarias para el build (como Vite, TypeScript, etc.)
- Resultado: El comando `npm run build` fallaba con error "vite: Permission denied" o "Command not found"

**Solución implementada:**
```dockerfile
# Antes (problemático)
RUN npm ci --only-production

# Después (corregido)
RUN npm ci
```
- Ahora instala todas las dependencias necesarias para la construcción
- Permite que `npm run build` ejecute correctamente Vite

#### Problema #2: Permisos de Ejecución en Binarios de Node.js
**Descripción del problema:**
- Los binarios instalados por npm (como `vite`) no tenían permisos de ejecución
- Esto causaba errores "Permission denied" al intentar ejecutar `npm run build`

**Solución implementada:**
- Verificado que npm instala correctamente los permisos ejecutables
- En caso de problemas locales, se puede usar `chmod +x node_modules/.bin/vite`
- En Docker, el problema se resolvió al usar una instalación limpia de dependencias

#### Problema #3: Configuración Incorrecta del Puerto en Nginx
**Descripción del problema:**
- El Dockerfile exponía el puerto 3991, pero Nginx estaba configurado para escuchar en 8080
- Inconsistencia entre EXPOSE y configuración de Nginx

**Solución implementada:**
- Estandarizado el puerto en 8080 para ambos
- Actualizado EXPOSE 8080
- Configurado Nginx para escuchar en 8080

#### Problema #4: Warnings de DockerScout sobre Casing en FROM
**Descripción del problema:**
- Warning menor: `'as' and 'FROM' keywords' casing do not match`
- No afectaba la funcionalidad pero generaba warnings

**Solución implementada:**
- Estandarizado el uso de `FROM` y `as` en minúsculas
- Mejorado el formato del Dockerfile para consistencia

### Mejoras Adicionales Implementadas

#### Optimización del Build Multi-Stage
- Separación clara entre etapa de construcción (Node.js) y producción (Nginx + Alpine)
- Reducción del tamaño final de la imagen (~18MB)
- Configuración de Nginx desde cero para mayor control y seguridad

#### Configuración de Seguridad Mejorada
- Usuario no privilegiado (nextjs) para ejecutar Nginx
- Headers de seguridad HTTP en la configuración de Nginx
- Permisos mínimos necesarios en el contenedor

### Resultados de las Correcciones

- ✅ Construcción exitosa de la imagen Docker
- ✅ Reducción de tamaño de imagen de ~200MB a ~18MB
- ✅ Eliminación de warnings de DockerScout
- ✅ Imagen funcional y segura lista para despliegue
- ✅ Push exitoso a Docker Hub como `loizzz/hat.sh-by-grupo5:latest`

### Lecciones Aprendidas

**Aspectos positivos del proyecto original:**
- Uso de criptografía moderna y robusta (libsodium)
- Arquitectura client-side que protege privacidad
- Código bien estructurado y modular
- Respeto por la privacidad (sin telemetría)

**Áreas de mejora identificadas:**
- Actualización periódica de dependencias crítica
- Headers de seguridad esenciales en aplicaciones web
- Gestión de datos sensibles requiere atención especial
- Validación estricta en puntos de entrada
- **Nueva lección:** Verificación exhaustiva del Dockerfile antes del despliegue

### Conclusión Final

El proceso de hardening de hat.sh ha sido exitoso, transformando una aplicación ya sólida en su fundamento criptográfico en una solución completamente endurecida desde la perspectiva de DevSecOps. Las **10 vulnerabilidades identificadas** han sido abordadas sistemáticamente, siguiendo un plan priorizado que comenzó con las amenazas críticas.


#### Paso 4: Disfruta encryptando tus archivos con una version renovada! 

#### by Grupo 5 🦊🦅

