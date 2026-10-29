/**
 * WebSentinel-CS :: Quality Corpus Benchmark (FASE 3 - P1)
 * Validates detection accuracy (100% true positives) and zero false positives (0% false alarms)
 * across real-world attacks and legitimate Spanish linguistic patterns.
 */

const { test, describe } = require('node:test');
const assert = require('node:assert');
const { inspectPayload } = require('../src/engine/signatures');

describe('WebSentinel-CS :: Quality Corpus Benchmark', () => {

  // ---------------------------------------------------------------------------
  // 1. Corpus de Ataques Reales (Mínimo 15 vectores de ataque reales)
  // Expected: 100% de detección (safe: false, scoreTotal > 0)
  // ---------------------------------------------------------------------------
  const MALICIOUS_CORPUS = [
    // SQL Injection
    { id: 'MAL-SQL-01', type: 'SQLi', payload: "' OR 1=1 --" },
    { id: 'MAL-SQL-02', type: 'SQLi', payload: "admin' OR '1'='1" },
    { id: 'MAL-SQL-03', type: 'SQLi', payload: "1 UNION SELECT null, username, password FROM users" },
    { id: 'MAL-SQL-04', type: 'SQLi', payload: "1; DROP TABLE users; --" },
    { id: 'MAL-SQL-05', type: 'SQLi', payload: "1' AND (SELECT 1 FROM (SELECT SLEEP(5))a)--" },
    { id: 'MAL-SQL-06', type: 'SQLi', payload: "1' AND @@version=1--" },
    { id: 'MAL-SQL-07', type: 'SQLi', payload: "SELECT CASE WHEN (1=1) THEN 1 ELSE 0 END" },
    { id: 'MAL-SQL-08', type: 'SQLi', payload: "%27%20UNION%20SELECT%201,2,3--" },
    { id: 'MAL-SQL-09', type: 'SQLi', payload: "%2527%20OR%201=1" },

    // Cross-Site Scripting (XSS)
    { id: 'MAL-XSS-01', type: 'XSS', payload: "<script>alert('pwned')</script>" },
    { id: 'MAL-XSS-02', type: 'XSS', payload: "<svg/onanimationstart=alert(1)>" },
    { id: 'MAL-XSS-03', type: 'XSS', payload: '<img src="x" onerror="alert(document.cookie)">' },
    { id: 'MAL-XSS-04', type: 'XSS', payload: '<iframe src="javascript:alert(1)"></iframe>' },
    { id: 'MAL-XSS-05', type: 'XSS', payload: '<a href="javascript:alert(1)">Click Me</a>' },
    { id: 'MAL-XSS-06', type: 'XSS', payload: 'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==' },

    // Path Traversal / LFI
    { id: 'MAL-PATH-01', type: 'Path Traversal', payload: '../../../../etc/passwd' },
    { id: 'MAL-PATH-02', type: 'Path Traversal', payload: '..\\..\\windows\\win.ini' },
    { id: 'MAL-PATH-03', type: 'LFI', payload: '/var/www/html/.env' },
    { id: 'MAL-PATH-04', type: 'LFI', payload: '/app/.git/config' },

    // Command Injection
    { id: 'MAL-CMD-01', type: 'Command Injection', payload: '; cat /etc/passwd' },
    { id: 'MAL-CMD-02', type: 'Command Injection', payload: '|| whoami' },
    { id: 'MAL-CMD-03', type: 'Command Injection', payload: 'file.txt; id' },
    { id: 'MAL-CMD-04', type: 'Command Injection', payload: '`id`' }
  ];

  describe('Corpus de Ataques Reales (Verificación de Detección 100%)', () => {
    for (const item of MALICIOUS_CORPUS) {
      test(`[${item.id}] Detecta vector ${item.type}: "${item.payload.substring(0, 35)}..."`, () => {
        const result = inspectPayload(item.payload);
        assert.strictEqual(
          result.safe,
          false,
          `El payload malicioso [${item.id}] debió ser detectado: ${item.payload}`
        );
        assert.ok(
          result.scoreTotal > 0,
          `El puntaje de anomalía debe ser mayor a 0 para [${item.id}]`
        );
        assert.ok(
          result.triggeredRules.length > 0,
          `Debe activar al menos una regla para [${item.id}]`
        );
      });
    }

    test('Tasa de detección global del corpus malicioso es 100%', () => {
      let detectedCount = 0;
      for (const item of MALICIOUS_CORPUS) {
        const res = inspectPayload(item.payload);
        if (!res.safe && res.scoreTotal > 0) {
          detectedCount++;
        }
      }
      const detectionRate = (detectedCount / MALICIOUS_CORPUS.length) * 100;
      assert.strictEqual(detectionRate, 100, `La tasa de detección debe ser 100%, fue ${detectionRate}%`);
    });
  });

  // ---------------------------------------------------------------------------
  // 2. Corpus de Textos Benignos en Español (Mínimo 15 casos legítimos)
  // Expected: 0% de falsos positivos (safe: true, scoreTotal === 0)
  // ---------------------------------------------------------------------------
  const BENIGN_CORPUS = [
    { id: 'BEN-01', text: "O'Reilly es una editorial prestigiosa de libros sobre ingeniería de software." },
    { id: 'BEN-02', text: "Este es un texto explicativo -- con guión doble para separar ideas en prosa." },
    { id: 'BEN-03', text: "Para consultas de mensajería, comuníquese a soporte@enviaexpress.com." },
    { id: 'BEN-04', text: "Documentación técnica: SELECT * FROM doc_templates WHERE id = 1 en plantilla." },
    { id: 'BEN-05', text: "La niña jugó en el jardín con su muñeca durante la tarde de otoño." },
    { id: 'BEN-06', text: "¿Cuál es el costo del trámite oficial para la expedición de cédula de extranjería?" },
    { id: 'BEN-07', text: "El funcionario Carlos Gómez inició sesión correctamente en el módulo de ventanilla única." },
    { id: 'BEN-08', text: "Parámetros de configuración del sistema: timeout=30s, retries=3, persist=true." },
    { id: 'BEN-09', text: "Factura de venta #4902 - Valor liquidado: $1.250.000 COP con fecha límite de pago." },
    { id: 'BEN-10', text: "Dirección de notificación judicial: Calle 72 # 10-34, Piso 4, Bogotá D.C." },
    { id: 'BEN-11', text: "¡Gran promoción de fin de año! Disfruta hasta un 30% de descuento en suscripciones anuales." },
    { id: 'BEN-12', text: "Ficha técnica del automotor: Placa KLS-892, Línea Sedan, Modelo 2023, Cilindraje 1600cc." },
    { id: 'BEN-13', text: "Resultado de búsqueda: visualizando registros donde estado = 'ACTIVO' en el listado general." },
    { id: 'BEN-14', text: "El informe de gestión trimestral y el balance general se adjuntan en formatos PDF y XLSX." },
    { id: 'BEN-15', text: "Procedimiento de atención: radicación de peticiones, quejas y reclamos ante la entidad pública." },
    { id: 'BEN-16', text: "Comentario del usuario: 'La plataforma me pareció intuitiva, rápida y muy fácil de usar'." },
    { id: 'BEN-17', text: "El equipo de desarrollo concluyó la entrega de la fase final sin contratiempos." }
  ];

  describe('Corpus de Textos Benignos (Verificación de Falsos Positivos 0%)', () => {
    for (const item of BENIGN_CORPUS) {
      test(`[${item.id}] No marca falso positivo para: "${item.text.substring(0, 35)}..."`, () => {
        const result = inspectPayload(item.text);
        assert.strictEqual(
          result.safe,
          true,
          `Falso positivo detectado en [${item.id}]: "${item.text}". Reglas disparadas: ${JSON.stringify(result.triggeredRules)}`
        );
        assert.strictEqual(
          result.scoreTotal,
          0,
          `El puntaje de anomalía debe ser 0 para texto legítimo [${item.id}]`
        );
        assert.strictEqual(
          result.triggeredRules.length,
          0,
          `No debe disparar ninguna regla para [${item.id}]`
        );
      });
    }

    test('Tasa de falsos positivos global del corpus benigno es 0%', () => {
      let falsePositives = 0;
      for (const item of BENIGN_CORPUS) {
        const res = inspectPayload(item.text);
        if (!res.safe || res.scoreTotal > 0 || res.triggeredRules.length > 0) {
          falsePositives++;
        }
      }
      assert.strictEqual(falsePositives, 0, `No debe haber falsos positivos. Hubo: ${falsePositives}`);
    });
  });
});
