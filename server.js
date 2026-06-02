'use strict';

const fastify = require('fastify')({ logger: true });
const bcrypt = require('bcrypt');
const { Pool } = require('pg');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const db = new Pool({
  host: process.env.DB_HOST || 'kaniene_postgres',
  port: 5432,
  database: process.env.DB_NAME || 'kaniene_prod',
  user: process.env.DB_USER || 'kaniene',
  password: process.env.DB_PASSWORD,
});

const UPLOAD_DIR = '/app/uploads/products';
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

fastify.register(require('@fastify/cors'), { origin: true });
fastify.register(require('@fastify/jwt'), { secret: process.env.JWT_SECRET || 'utiam_secret_key' });
fastify.register(require('@fastify/multipart'), { limits: { fileSize: 10 * 1024 * 1024 } });
fastify.register(require('@fastify/static'), { root: UPLOAD_DIR, prefix: '/uploads/products/' });

fastify.decorate('authenticate', async function(request, reply) {
  try { await request.jwtVerify(); }
  catch (err) { reply.status(401).send({ error: 'Non autorise' }); }
});

function validatePasswordStrength(password) {
  if (!password || typeof password !== 'string') return 'Mot de passe requis';
  if (password.length < 8) return 'Le mot de passe doit contenir au moins 8 caracteres';
  if (!/[0-9]/.test(password)) return 'Le mot de passe doit contenir au moins 1 chiffre';
  if (!/[A-Z]/.test(password)) return 'Le mot de passe doit contenir au moins 1 majuscule';
  return null;
}

fastify.get('/health', async () => ({ status: 'ok', app: 'U TIAM' }));

// ─── AUTH ─────────────────────────────────────────────────
fastify.post('/api/auth/login', async (request, reply) => {
  const { email, password } = request.body;
  const result = await db.query('SELECT * FROM utiam_users WHERE email = $1 AND is_active = true', [email]);
  if (result.rows.length === 0) return reply.status(401).send({ error: 'Email ou mot de passe incorrect' });
  const user = result.rows[0];
  const valid = await bcrypt.compare(password, user.password_hash);
  if (!valid) return reply.status(401).send({ error: 'Email ou mot de passe incorrect' });
  const token = fastify.jwt.sign({ id: user.id, email: user.email, role: user.role, display_name: user.display_name }, { expiresIn: '24h' });
  return {
    token,
    user: { id: user.id, email: user.email, role: user.role, display_name: user.display_name, must_change_password: user.must_change_password === true }
  };
});

// ─── CATEGORIES ───────────────────────────────────────────
fastify.get('/api/categories', { onRequest: [fastify.authenticate] }, async () => {
  const result = await db.query('SELECT * FROM utiam_categories ORDER BY name');
  return result.rows;
});
fastify.post('/api/categories', { onRequest: [fastify.authenticate] }, async (request, reply) => {
  const { name } = request.body;
  const result = await db.query('INSERT INTO utiam_categories (name) VALUES ($1) RETURNING *', [name]);
  return reply.status(201).send(result.rows[0]);
});

// ─── PRODUITS ─────────────────────────────────────────────
fastify.get('/api/products', { onRequest: [fastify.authenticate] }, async (request) => {
  const { search, barcode, status, supplier_id } = request.query;
  if (barcode) {
    const result = await db.query("SELECT * FROM utiam_products WHERE barcode = $1 AND status = 'active'", [barcode]);
    return result.rows;
  }
  if (search) {
    const result = await db.query("SELECT * FROM utiam_products WHERE LOWER(name) LIKE LOWER($1) AND status = 'active' LIMIT 10", [`%${search}%`]);
    return result.rows;
  }
  let whereStatus = "p.status = 'active'";
  if (status === 'inactive')       whereStatus = "p.status = 'inactive'";
  else if (status === 'archived')  whereStatus = "p.status = 'archived'";
  else if (status === 'all')       whereStatus = "TRUE";

  let supplierJoin = '';
  let supplierWhere = '';
  const params = [];
  if (supplier_id) {
    supplierJoin = 'INNER JOIN utiam_product_suppliers psf ON psf.product_id = p.id';
    supplierWhere = `AND psf.supplier_id = $${params.length + 1}`;
    params.push(supplier_id);
  }

  const result = await db.query(`
    SELECT p.*, c.name AS category_name, pi.url AS primary_image_url
    FROM utiam_products p
    LEFT JOIN utiam_categories c ON p.category_id = c.id
    LEFT JOIN utiam_product_images pi ON pi.product_id = p.id AND pi.is_primary = TRUE
    ${supplierJoin}
    WHERE ${whereStatus} ${supplierWhere}
    ORDER BY p.name
  `, params);
  return result.rows;
});

fastify.post('/api/products', { onRequest: [fastify.authenticate] }, async (request, reply) => {
  const { name, barcode, buy_price, sell_price, category_id, brand, unit, stock, min_stock, expiry_date, image_url, status } = request.body;
  const result = await db.query(
    'INSERT INTO utiam_products (name, barcode, buy_price, sell_price, category_id, brand, unit, stock, min_stock, expiry_date, image_url, status) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) RETURNING *',
    [name, barcode, buy_price, sell_price, category_id, brand, unit || 'pcs', stock || 0, min_stock || 5, expiry_date || null, image_url || null, status || 'active']
  );
  return reply.status(201).send(result.rows[0]);
});

fastify.put('/api/products/:id', { onRequest: [fastify.authenticate] }, async (request, reply) => {
  const { name, barcode, buy_price, sell_price, category_id, brand, unit, stock, min_stock, expiry_date, image_url, status } = request.body;
  const result = await db.query(
    'UPDATE utiam_products SET name=$1, barcode=$2, buy_price=$3, sell_price=$4, category_id=$5, brand=$6, unit=$7, stock=$8, min_stock=$9, expiry_date=$10, image_url=$11, status=COALESCE($12, status), updated_at=NOW() WHERE id=$13 RETURNING *',
    [name, barcode, buy_price, sell_price, category_id, brand, unit, stock, min_stock, expiry_date || null, image_url || null, status || null, request.params.id]
  );
  return result.rows[0];
});

fastify.put('/api/products/:id/status', { onRequest: [fastify.authenticate] }, async (request, reply) => {
  const { status } = request.body;
  if (!['active', 'inactive', 'archived'].includes(status)) return reply.status(400).send({ error: 'Statut invalide' });
  const result = await db.query('UPDATE utiam_products SET status = $1, updated_at = NOW() WHERE id = $2 RETURNING *', [status, request.params.id]);
  return result.rows[0];
});

fastify.delete('/api/products/:id', { onRequest: [fastify.authenticate] }, async (request, reply) => {
  await db.query('DELETE FROM utiam_products WHERE id = $1', [request.params.id]);
  return reply.status(204).send();
});

// ─── IMPORT CSV ───────────────────────────────────────────
fastify.post('/api/products/import', { onRequest: [fastify.authenticate] }, async (request, reply) => {
  const { rows } = request.body;
  if (!Array.isArray(rows)) return reply.status(400).send({ error: 'Format invalide : rows attendu' });
  const client = await db.connect();
  const report = { created: 0, updated: 0, skipped: 0, errors: [] };
  const catCache = {};
  const allCats = await client.query('SELECT id, LOWER(name) as lname FROM utiam_categories');
  for (const c of allCats.rows) catCache[c.lname] = c.id;
  try {
    await client.query('BEGIN');
    for (let i = 0; i < rows.length; i++) {
      const row = rows[i];
      const data = row.data || {};
      const action = row.action || 'create';
      if (action === 'skip') { report.skipped++; continue; }
      try {
        let categoryId = null;
        if (data.category && String(data.category).trim()) {
          const catName = String(data.category).trim();
          const lname = catName.toLowerCase();
          if (catCache[lname]) categoryId = catCache[lname];
          else {
            const newCat = await client.query('INSERT INTO utiam_categories (name) VALUES ($1) RETURNING id', [catName]);
            categoryId = newCat.rows[0].id;
            catCache[lname] = categoryId;
          }
        }
        if (!data.name || String(data.name).trim() === '') { report.errors.push({ line: i + 1, error: 'Nom manquant' }); continue; }
        if (!data.sell_price || isNaN(Number(data.sell_price))) { report.errors.push({ line: i + 1, error: 'Prix de vente invalide' }); continue; }
        const payload = [
          String(data.name).trim(),
          data.barcode ? String(data.barcode).trim() : null,
          data.buy_price ? Number(data.buy_price) : null,
          Number(data.sell_price),
          categoryId,
          data.brand ? String(data.brand).trim() : null,
          data.unit ? String(data.unit).trim() : 'pcs',
          data.stock ? Number(data.stock) : 0,
          data.min_stock ? Number(data.min_stock) : 5,
          data.expiry_date && String(data.expiry_date).trim() ? data.expiry_date : null,
        ];
        if (action === 'update' && row.existing_id) {
          await client.query(
            'UPDATE utiam_products SET name=$1, barcode=$2, buy_price=$3, sell_price=$4, category_id=$5, brand=$6, unit=$7, stock=$8, min_stock=$9, expiry_date=$10, updated_at=NOW() WHERE id=$11',
            [...payload, row.existing_id]
          );
          report.updated++;
        } else {
          await client.query(
            "INSERT INTO utiam_products (name, barcode, buy_price, sell_price, category_id, brand, unit, stock, min_stock, expiry_date, status) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'active')",
            payload
          );
          report.created++;
        }
      } catch (err) { report.errors.push({ line: i + 1, error: err.message }); }
    }
    await client.query('COMMIT');
    return report;
  } catch (err) { await client.query('ROLLBACK'); throw err; }
  finally { client.release(); }
});

fastify.post('/api/products/check-duplicates', { onRequest: [fastify.authenticate] }, async (request) => {
  const { barcodes } = request.body;
  if (!Array.isArray(barcodes) || barcodes.length === 0) return {};
  const result = await db.query('SELECT id, name, barcode FROM utiam_products WHERE barcode = ANY($1)', [barcodes]);
  const map = {};
  for (const r of result.rows) map[r.barcode] = { id: r.id, name: r.name };
  return map;
});

// ─── IMAGES PRODUITS ──────────────────────────────────────
fastify.get('/api/products/:id/images', { onRequest: [fastify.authenticate] }, async (request) => {
  const result = await db.query('SELECT * FROM utiam_product_images WHERE product_id = $1 ORDER BY is_primary DESC, position ASC, id ASC', [request.params.id]);
  return result.rows;
});

fastify.post('/api/products/:id/images', { onRequest: [fastify.authenticate] }, async (request, reply) => {
  const productId = request.params.id;
  const prodCheck = await db.query('SELECT id FROM utiam_products WHERE id = $1', [productId]);
  if (prodCheck.rows.length === 0) return reply.status(404).send({ error: 'Produit introuvable' });
  const data = await request.file();
  if (!data) return reply.status(400).send({ error: 'Aucun fichier fourni' });
  if (!data.mimetype.startsWith('image/')) return reply.status(400).send({ error: 'Le fichier doit etre une image' });
  const sharp = require('sharp');
  const ext = '.webp';
  const filename = `${productId}_${Date.now()}_${crypto.randomBytes(4).toString('hex')}${ext}`;
  const filepath = path.join(UPLOAD_DIR, filename);
  const buffer = await data.toBuffer();
  await sharp(buffer).resize(1200, 1200, { fit: 'inside', withoutEnlargement: true }).webp({ quality: 80 }).toFile(filepath);
  const url = `/uploads/products/${filename}`;
  const existing = await db.query('SELECT COUNT(*) as cnt FROM utiam_product_images WHERE product_id = $1', [productId]);
  const isPrimary = parseInt(existing.rows[0].cnt) === 0;
  const result = await db.query(
    'INSERT INTO utiam_product_images (product_id, filename, url, is_primary, position) VALUES ($1, $2, $3, $4, $5) RETURNING *',
    [productId, filename, url, isPrimary, parseInt(existing.rows[0].cnt)]
  );
  return reply.status(201).send(result.rows[0]);
});

fastify.put('/api/products/:id/images/:imageId/primary', { onRequest: [fastify.authenticate] }, async (request, reply) => {
  const { id, imageId } = request.params;
  const client = await db.connect();
  try {
    await client.query('BEGIN');
    await client.query('UPDATE utiam_product_images SET is_primary = FALSE WHERE product_id = $1', [id]);
    await client.query('UPDATE utiam_product_images SET is_primary = TRUE WHERE id = $1 AND product_id = $2', [imageId, id]);
    await client.query('COMMIT');
    return { success: true };
  } catch (err) { await client.query('ROLLBACK'); throw err; }
  finally { client.release(); }
});

fastify.delete('/api/images/:imageId', { onRequest: [fastify.authenticate] }, async (request, reply) => {
  const imageId = request.params.imageId;
  const imgResult = await db.query('SELECT * FROM utiam_product_images WHERE id = $1', [imageId]);
  if (imgResult.rows.length === 0) return reply.status(404).send({ error: 'Image introuvable' });
  const img = imgResult.rows[0];
  const filepath = path.join(UPLOAD_DIR, img.filename);
  if (fs.existsSync(filepath)) fs.unlinkSync(filepath);
  await db.query('DELETE FROM utiam_product_images WHERE id = $1', [imageId]);
  if (img.is_primary) {
    await db.query(
      'UPDATE utiam_product_images SET is_primary = TRUE WHERE id = (SELECT id FROM utiam_product_images WHERE product_id = $1 ORDER BY position ASC LIMIT 1)',
      [img.product_id]
    );
  }
  return reply.status(204).send();
});


// ═════════════════════════════════════════════════════════
// ─── FOURNISSEURS ─────────────────────────────────────────
// ═════════════════════════════════════════════════════════

// Liste des fournisseurs avec stats
fastify.get('/api/suppliers', { onRequest: [fastify.authenticate] }, async (request) => {
  const { active } = request.query;
  let whereActive = '';
  if (active === 'true') whereActive = 'WHERE s.is_active = TRUE';
  else if (active === 'false') whereActive = 'WHERE s.is_active = FALSE';

  const result = await db.query(`
    SELECT s.*,
           COALESCE(stats.products_count, 0) as products_count,
           COALESCE(pos.total_received, 0) as total_received,
           pos.last_delivery,
           COALESCE(pos.po_count, 0) as po_count,
           COALESCE(pos.po_total, 0) as po_total,
           COALESCE(payments.total_paid, 0) as total_paid
    FROM utiam_suppliers s
    LEFT JOIN (
      SELECT supplier_id, COUNT(DISTINCT product_id) as products_count
      FROM utiam_product_suppliers GROUP BY supplier_id
    ) stats ON stats.supplier_id = s.id
    LEFT JOIN (
      SELECT po.supplier_id,
             SUM(CASE WHEN po.status IN ('received', 'partial', 'settled') THEN po.total ELSE 0 END) as total_received,
             MAX(po.received_at) as last_delivery,
             COUNT(po.id) as po_count,
             SUM(po.total) as po_total
      FROM utiam_purchase_orders po GROUP BY po.supplier_id
    ) pos ON pos.supplier_id = s.id
    LEFT JOIN (
      SELECT supplier_id, SUM(amount) as total_paid
      FROM utiam_supplier_payments GROUP BY supplier_id
    ) payments ON payments.supplier_id = s.id
    ${whereActive}
    ORDER BY s.name
  `);
  return result.rows;
});

// Detail d'un fournisseur
fastify.get('/api/suppliers/:id', { onRequest: [fastify.authenticate] }, async (request, reply) => {
  const { id } = request.params;
  const supplierRes = await db.query('SELECT * FROM utiam_suppliers WHERE id = $1', [id]);
  if (supplierRes.rows.length === 0) return reply.status(404).send({ error: 'Fournisseur introuvable' });

  const products = await db.query(`
    SELECT ps.*, p.name as product_name, p.unit, p.stock
    FROM utiam_product_suppliers ps
    JOIN utiam_products p ON p.id = ps.product_id
    WHERE ps.supplier_id = $1
    ORDER BY p.name
  `, [id]);

  const purchaseOrders = await db.query(`
    SELECT po.*, u.display_name as user_name,
           (SELECT COUNT(*) FROM utiam_purchase_order_items WHERE purchase_order_id = po.id) as items_count
    FROM utiam_purchase_orders po
    JOIN utiam_users u ON u.id = po.user_id
    WHERE po.supplier_id = $1
    ORDER BY po.created_at DESC LIMIT 50
  `, [id]);

  const payments = await db.query(`
    SELECT sp.*, u.display_name as user_name, po.reference as po_reference
    FROM utiam_supplier_payments sp
    JOIN utiam_users u ON u.id = sp.user_id
    LEFT JOIN utiam_purchase_orders po ON po.id = sp.purchase_order_id
    WHERE sp.supplier_id = $1
    ORDER BY sp.created_at DESC LIMIT 50
  `, [id]);

  const balanceRes = await db.query(`
    SELECT
      COALESCE((SELECT SUM(total) FROM utiam_purchase_orders WHERE supplier_id = $1 AND status IN ('received', 'settled')), 0) as total_received,
      COALESCE((SELECT SUM(amount) FROM utiam_supplier_payments WHERE supplier_id = $1), 0) as total_paid
  `, [id]);
  const balance = Number(balanceRes.rows[0].total_received) - Number(balanceRes.rows[0].total_paid);

  return {
    ...supplierRes.rows[0],
    products: products.rows,
    purchase_orders: purchaseOrders.rows,
    payments: payments.rows,
    balance,
    total_received: Number(balanceRes.rows[0].total_received),
    total_paid: Number(balanceRes.rows[0].total_paid),
  };
});

fastify.post('/api/suppliers', { onRequest: [fastify.authenticate] }, async (request, reply) => {
  const { name, phone, email, address, payment_terms, notes } = request.body;
  if (!name || !String(name).trim()) return reply.status(400).send({ error: 'Le nom est obligatoire' });
  const result = await db.query(
    'INSERT INTO utiam_suppliers (name, phone, email, address, payment_terms, notes) VALUES ($1,$2,$3,$4,$5,$6) RETURNING *',
    [String(name).trim(), phone || null, email || null, address || null, payment_terms || 'comptant', notes || null]
  );
  return reply.status(201).send(result.rows[0]);
});

fastify.put('/api/suppliers/:id', { onRequest: [fastify.authenticate] }, async (request) => {
  const { name, phone, email, address, payment_terms, notes } = request.body;
  const result = await db.query(
    'UPDATE utiam_suppliers SET name=$1, phone=$2, email=$3, address=$4, payment_terms=$5, notes=$6, updated_at=NOW() WHERE id=$7 RETURNING *',
    [name, phone || null, email || null, address || null, payment_terms || 'comptant', notes || null, request.params.id]
  );
  return result.rows[0];
});

fastify.put('/api/suppliers/:id/status', { onRequest: [fastify.authenticate] }, async (request, reply) => {
  const { is_active } = request.body;
  if (typeof is_active !== 'boolean') return reply.status(400).send({ error: 'is_active doit etre un booleen' });
  const result = await db.query(
    'UPDATE utiam_suppliers SET is_active = $1, updated_at = NOW() WHERE id = $2 RETURNING *',
    [is_active, request.params.id]
  );
  if (result.rows.length === 0) return reply.status(404).send({ error: 'Fournisseur introuvable' });
  return result.rows[0];
});

// ─── PRODUIT <-> FOURNISSEURS ────────────────────────────
fastify.get('/api/products/:id/suppliers', { onRequest: [fastify.authenticate] }, async (request) => {
  const result = await db.query(`
    SELECT ps.*, s.name as supplier_name, s.phone, s.email
    FROM utiam_product_suppliers ps
    JOIN utiam_suppliers s ON s.id = ps.supplier_id
    WHERE ps.product_id = $1
    ORDER BY ps.is_primary DESC, ps.unit_price ASC NULLS LAST
  `, [request.params.id]);
  return result.rows;
});

fastify.post('/api/products/:id/suppliers', { onRequest: [fastify.authenticate] }, async (request, reply) => {
  const { id } = request.params;
  const { supplier_id, unit_price, is_primary, notes } = request.body;
  if (!supplier_id) return reply.status(400).send({ error: 'supplier_id requis' });

  const client = await db.connect();
  try {
    await client.query('BEGIN');
    if (is_primary) {
      await client.query('UPDATE utiam_product_suppliers SET is_primary = FALSE WHERE product_id = $1', [id]);
    }
    const existing = await client.query('SELECT id FROM utiam_product_suppliers WHERE product_id = $1 AND supplier_id = $2', [id, supplier_id]);
    let result;
    if (existing.rows.length > 0) {
      result = await client.query(
        'UPDATE utiam_product_suppliers SET unit_price = $1, is_primary = $2, notes = $3 WHERE id = $4 RETURNING *',
        [unit_price || null, !!is_primary, notes || null, existing.rows[0].id]
      );
    } else {
      result = await client.query(
        'INSERT INTO utiam_product_suppliers (product_id, supplier_id, unit_price, is_primary, notes) VALUES ($1,$2,$3,$4,$5) RETURNING *',
        [id, supplier_id, unit_price || null, !!is_primary, notes || null]
      );
    }
    await client.query('COMMIT');
    return reply.status(201).send(result.rows[0]);
  } catch (err) { await client.query('ROLLBACK'); throw err; }
  finally { client.release(); }
});

fastify.put('/api/products/:id/suppliers/:supplierId/primary', { onRequest: [fastify.authenticate] }, async (request) => {
  const { id, supplierId } = request.params;
  const client = await db.connect();
  try {
    await client.query('BEGIN');
    await client.query('UPDATE utiam_product_suppliers SET is_primary = FALSE WHERE product_id = $1', [id]);
    await client.query('UPDATE utiam_product_suppliers SET is_primary = TRUE WHERE product_id = $1 AND supplier_id = $2', [id, supplierId]);
    await client.query('COMMIT');
    return { success: true };
  } catch (err) { await client.query('ROLLBACK'); throw err; }
  finally { client.release(); }
});

fastify.delete('/api/products/:id/suppliers/:supplierId', { onRequest: [fastify.authenticate] }, async (request, reply) => {
  const { id, supplierId } = request.params;
  await db.query('DELETE FROM utiam_product_suppliers WHERE product_id = $1 AND supplier_id = $2', [id, supplierId]);
  return reply.status(204).send();
});

// ─── BONS DE COMMANDE ─────────────────────────────────────
fastify.get('/api/purchase-orders', { onRequest: [fastify.authenticate] }, async (request) => {
  const { status, supplier_id } = request.query;
  const conditions = [];
  const params = [];
  if (status) { conditions.push(`po.status = $${params.length + 1}`); params.push(status); }
  if (supplier_id) { conditions.push(`po.supplier_id = $${params.length + 1}`); params.push(supplier_id); }
  const where = conditions.length > 0 ? 'WHERE ' + conditions.join(' AND ') : '';

  const result = await db.query(`
    SELECT po.*, s.name as supplier_name, u.display_name as user_name,
           (SELECT COUNT(*) FROM utiam_purchase_order_items WHERE purchase_order_id = po.id) as items_count
    FROM utiam_purchase_orders po
    JOIN utiam_suppliers s ON s.id = po.supplier_id
    JOIN utiam_users u ON u.id = po.user_id
    ${where}
    ORDER BY po.created_at DESC
  `, params);
  return result.rows;
});

fastify.get('/api/purchase-orders/:id', { onRequest: [fastify.authenticate] }, async (request, reply) => {
  const { id } = request.params;
  const poRes = await db.query(`
    SELECT po.*, s.name as supplier_name, s.phone as supplier_phone, s.email as supplier_email,
           s.address as supplier_address, s.payment_terms, u.display_name as user_name
    FROM utiam_purchase_orders po
    JOIN utiam_suppliers s ON s.id = po.supplier_id
    JOIN utiam_users u ON u.id = po.user_id
    WHERE po.id = $1
  `, [id]);
  if (poRes.rows.length === 0) return reply.status(404).send({ error: 'Bon de commande introuvable' });

  const items = await db.query(`
    SELECT poi.*, p.unit FROM utiam_purchase_order_items poi
    LEFT JOIN utiam_products p ON p.id = poi.product_id
    WHERE poi.purchase_order_id = $1
    ORDER BY poi.id ASC
  `, [id]);

  return { ...poRes.rows[0], items: items.rows };
});

fastify.post('/api/purchase-orders', { onRequest: [fastify.authenticate] }, async (request, reply) => {
  const { supplier_id, items, expected_date, notes } = request.body;
  const user_id = request.user.id;
  if (!supplier_id) return reply.status(400).send({ error: 'supplier_id requis' });
  if (!Array.isArray(items) || items.length === 0) return reply.status(400).send({ error: 'Aucun article' });

  const reference = 'BC-' + Date.now();
  const total = items.reduce((s, i) => s + (Number(i.quantity_ordered) * Number(i.unit_price || 0)), 0);

  const client = await db.connect();
  try {
    await client.query('BEGIN');
    const poRes = await client.query(
      'INSERT INTO utiam_purchase_orders (reference, supplier_id, status, total, expected_date, notes, user_id) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *',
      [reference, supplier_id, 'draft', total, expected_date || null, notes || null, user_id]
    );
    const po = poRes.rows[0];

    for (const item of items) {
      if (!item.product_id || !item.quantity_ordered) continue;
      const prodRes = await client.query('SELECT name FROM utiam_products WHERE id = $1', [item.product_id]);
      const productName = prodRes.rows[0]?.name || 'Produit inconnu';
      const itemTotal = Number(item.quantity_ordered) * Number(item.unit_price || 0);
      await client.query(
        'INSERT INTO utiam_purchase_order_items (purchase_order_id, product_id, product_name, quantity_ordered, unit_price, total) VALUES ($1,$2,$3,$4,$5,$6)',
        [po.id, item.product_id, productName, item.quantity_ordered, item.unit_price || null, itemTotal]
      );
    }
    await client.query('COMMIT');
    return reply.status(201).send(po);
  } catch (err) { await client.query('ROLLBACK'); throw err; }
  finally { client.release(); }
});

fastify.put('/api/purchase-orders/:id/status', { onRequest: [fastify.authenticate] }, async (request, reply) => {
  const { id } = request.params;
  const { status } = request.body;
  if (!['draft', 'sent', 'received', 'partial', 'settled', 'cancelled'].includes(status)) {
    return reply.status(400).send({ error: 'Statut invalide' });
  }
  let extraSet = '';
  if (status === 'sent') extraSet = ', sent_at = COALESCE(sent_at, NOW())';
  else if (status === 'received' || status === 'partial') extraSet = ', received_at = COALESCE(received_at, NOW())';

  const result = await db.query(
    `UPDATE utiam_purchase_orders SET status = $1${extraSet} WHERE id = $2 RETURNING *`,
    [status, id]
  );
  if (result.rows.length === 0) return reply.status(404).send({ error: 'BC introuvable' });
  return result.rows[0];
});

fastify.delete('/api/purchase-orders/:id', { onRequest: [fastify.authenticate] }, async (request, reply) => {
  const { id } = request.params;
  const poRes = await db.query('SELECT status FROM utiam_purchase_orders WHERE id = $1', [id]);
  if (poRes.rows.length === 0) return reply.status(404).send({ error: 'BC introuvable' });
  if (poRes.rows[0].status !== 'draft') {
    return reply.status(409).send({ error: 'Seuls les brouillons peuvent etre supprimes. Utilisez "Annuler" pour les BC envoyes.' });
  }
  await db.query('DELETE FROM utiam_purchase_orders WHERE id = $1', [id]);
  return reply.status(204).send();
});

// ─── PAIEMENTS FOURNISSEURS ──────────────────────────────
fastify.get('/api/suppliers/:id/payments', { onRequest: [fastify.authenticate] }, async (request) => {
  const result = await db.query(`
    SELECT sp.*, u.display_name as user_name, po.reference as po_reference
    FROM utiam_supplier_payments sp
    JOIN utiam_users u ON u.id = sp.user_id
    LEFT JOIN utiam_purchase_orders po ON po.id = sp.purchase_order_id
    WHERE sp.supplier_id = $1
    ORDER BY sp.created_at DESC
  `, [request.params.id]);
  return result.rows;
});

fastify.post('/api/supplier-payments', { onRequest: [fastify.authenticate] }, async (request, reply) => {
  const { supplier_id, purchase_order_id, amount, payment_method, reference, notes } = request.body;
  const user_id = request.user.id;
  if (!supplier_id || !amount || !payment_method) return reply.status(400).send({ error: 'supplier_id, amount, payment_method requis' });

  const client = await db.connect();
  try {
    await client.query('BEGIN');
    const result = await client.query(
      'INSERT INTO utiam_supplier_payments (supplier_id, purchase_order_id, amount, payment_method, reference, notes, user_id) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *',
      [supplier_id, purchase_order_id || null, Number(amount), payment_method, reference || null, notes || null, user_id]
    );

    if (purchase_order_id) {
      const poRes = await client.query('SELECT total FROM utiam_purchase_orders WHERE id = $1', [purchase_order_id]);
      const totalPaidRes = await client.query('SELECT COALESCE(SUM(amount), 0) as total FROM utiam_supplier_payments WHERE purchase_order_id = $1', [purchase_order_id]);
      if (poRes.rows.length > 0) {
        const total = Number(poRes.rows[0].total);
        const paid = Number(totalPaidRes.rows[0].total);
        if (paid >= total) {
          await client.query("UPDATE utiam_purchase_orders SET status = 'settled' WHERE id = $1 AND status = 'received'", [purchase_order_id]);
        }
      }
    }

    await client.query('COMMIT');
    return reply.status(201).send(result.rows[0]);
  } catch (err) { await client.query('ROLLBACK'); throw err; }
  finally { client.release(); }
});


// ─── CLIENTS ──────────────────────────────────────────────
fastify.get('/api/clients', { onRequest: [fastify.authenticate] }, async () => {
  const result = await db.query(`
    SELECT c.*,
           COALESCE(stats.visits, 0) as visits,
           COALESCE(stats.total_spent, 0) as total_spent,
           stats.last_visit
    FROM utiam_clients c
    LEFT JOIN (
      SELECT client_id, COUNT(*) as visits, SUM(total) as total_spent, MAX(created_at) as last_visit
      FROM utiam_sales WHERE client_id IS NOT NULL GROUP BY client_id
    ) stats ON stats.client_id = c.id
    ORDER BY c.name
  `);
  return result.rows;
});

fastify.get('/api/clients/:id', { onRequest: [fastify.authenticate] }, async (request, reply) => {
  const { id } = request.params;
  const clientRes = await db.query('SELECT * FROM utiam_clients WHERE id = $1', [id]);
  if (clientRes.rows.length === 0) return reply.status(404).send({ error: 'Client introuvable' });
  const stats = await db.query(`
    SELECT COUNT(*) as visits, COALESCE(SUM(total), 0) as total_spent, COALESCE(AVG(total), 0) as avg_basket,
           MAX(created_at) as last_visit, MIN(created_at) as first_visit
    FROM utiam_sales WHERE client_id = $1
  `, [id]);
  return { ...clientRes.rows[0], stats: stats.rows[0] };
});

fastify.get('/api/clients/:id/history', { onRequest: [fastify.authenticate] }, async (request) => {
  const { id } = request.params;
  const sales = await db.query(`
    SELECT s.*, u.display_name as cashier_name,
           json_agg(json_build_object('product_name', si.product_name, 'quantity', si.quantity, 'price', si.price, 'total', si.total)) as items
    FROM utiam_sales s
    LEFT JOIN utiam_users u ON s.cashier_id = u.id
    LEFT JOIN utiam_sale_items si ON si.sale_id = s.id
    WHERE s.client_id = $1
    GROUP BY s.id, u.display_name
    ORDER BY s.created_at DESC LIMIT 100
  `, [id]);
  return sales.rows;
});

fastify.post('/api/clients', { onRequest: [fastify.authenticate] }, async (request, reply) => {
  const { name, phone, email } = request.body;
  if (!name || !String(name).trim()) return reply.status(400).send({ error: 'Le nom est obligatoire' });
  const result = await db.query('INSERT INTO utiam_clients (name, phone, email) VALUES ($1,$2,$3) RETURNING *', [String(name).trim(), phone || null, email || null]);
  return reply.status(201).send(result.rows[0]);
});

fastify.put('/api/clients/:id', { onRequest: [fastify.authenticate] }, async (request) => {
  const { name, phone, email, credit, loyalty_points } = request.body;
  const result = await db.query(
    'UPDATE utiam_clients SET name=$1, phone=$2, email=$3, credit=COALESCE($4, credit), loyalty_points=COALESCE($5, loyalty_points) WHERE id=$6 RETURNING *',
    [name, phone || null, email || null, credit ?? null, loyalty_points ?? null, request.params.id]
  );
  return result.rows[0];
});

fastify.delete('/api/clients/:id', { onRequest: [fastify.authenticate] }, async (request, reply) => {
  const { id } = request.params;
  const salesCheck = await db.query('SELECT COUNT(*) as cnt FROM utiam_sales WHERE client_id = $1', [id]);
  if (parseInt(salesCheck.rows[0].cnt) > 0) {
    return reply.status(409).send({
      error: 'Ce client a ' + salesCheck.rows[0].cnt + ' vente(s) associee(s). Impossible de le supprimer.',
      sales_count: parseInt(salesCheck.rows[0].cnt)
    });
  }
  await db.query('DELETE FROM utiam_clients WHERE id = $1', [id]);
  return reply.status(204).send();
});

// ─── VENTES ───────────────────────────────────────────────
fastify.get('/api/sales', { onRequest: [fastify.authenticate] }, async (request) => {
  const limit = request.query.limit || 50;
  const result = await db.query(
    'SELECT s.*, u.display_name as cashier_name, c.name as client_name FROM utiam_sales s LEFT JOIN utiam_users u ON s.cashier_id = u.id LEFT JOIN utiam_clients c ON s.client_id = c.id ORDER BY s.created_at DESC LIMIT $1',
    [limit]
  );
  return result.rows;
});

fastify.post('/api/sales', { onRequest: [fastify.authenticate] }, async (request, reply) => {
  const { items, total, discount, payment_method, client_id } = request.body;
  const cashier_id = request.user.id;
  const client = await db.connect();
  try {
    await client.query('BEGIN');
    const saleResult = await client.query(
      'INSERT INTO utiam_sales (total, discount, payment_method, client_id, cashier_id) VALUES ($1,$2,$3,$4,$5) RETURNING *',
      [total, discount || 0, payment_method, client_id || null, cashier_id]
    );
    const sale = saleResult.rows[0];
    for (const item of items) {
      await client.query(
        'INSERT INTO utiam_sale_items (sale_id, product_id, product_name, price, quantity, total) VALUES ($1,$2,$3,$4,$5,$6)',
        [sale.id, item.product_id, item.product_name, item.price, item.quantity, item.total]
      );
      await client.query('UPDATE utiam_products SET stock = stock - $1, updated_at = NOW() WHERE id = $2', [item.quantity, item.product_id]);
      await client.query('INSERT INTO utiam_stock_movements (product_id, type, quantity, user_id) VALUES ($1, $2, $3, $4)', [item.product_id, 'sale', -item.quantity, cashier_id]);
    }
    await client.query('COMMIT');
    return reply.status(201).send(sale);
  } catch (err) { await client.query('ROLLBACK'); throw err; }
  finally { client.release(); }
});

// ─── STOCK ────────────────────────────────────────────────
fastify.get('/api/stock/movements', { onRequest: [fastify.authenticate] }, async (request) => {
  const { type, product_id, from, to, limit } = request.query;
  const conditions = [];
  const params = [];
  if (type) { conditions.push(`sm.type = $${params.length + 1}`); params.push(type); }
  if (product_id) { conditions.push(`sm.product_id = $${params.length + 1}`); params.push(product_id); }
  if (from) { conditions.push(`sm.created_at::date >= $${params.length + 1}`); params.push(from); }
  if (to) { conditions.push(`sm.created_at::date <= $${params.length + 1}`); params.push(to); }
  const where = conditions.length > 0 ? 'WHERE ' + conditions.join(' AND ') : '';
  params.push(Number(limit) || 200);
  const result = await db.query(
    `SELECT sm.*, p.name as product_name, p.unit, u.display_name as user_name
     FROM utiam_stock_movements sm
     JOIN utiam_products p ON sm.product_id = p.id
     JOIN utiam_users u ON sm.user_id = u.id
     ${where}
     ORDER BY sm.created_at DESC
     LIMIT $${params.length}`,
    params
  );
  return result.rows;
});

fastify.post('/api/stock/movements', { onRequest: [fastify.authenticate] }, async (request, reply) => {
  const { product_id, type, quantity, reason, unit_price } = request.body;
  const user_id = request.user.id;
  if (!['restock', 'adjustment'].includes(type)) return reply.status(400).send({ error: 'Type invalide. Utilisez restock ou adjustment.' });
  const client = await db.connect();
  try {
    await client.query('BEGIN');
    await client.query('INSERT INTO utiam_stock_movements (product_id, type, quantity, reason, unit_price, user_id) VALUES ($1,$2,$3,$4,$5,$6)', [product_id, type, quantity, reason || null, unit_price || null, user_id]);
    const delta = type === 'restock' ? Math.abs(quantity) : Number(quantity);
    await client.query('UPDATE utiam_products SET stock = stock + $1, updated_at = NOW() WHERE id = $2', [delta, product_id]);
    await client.query('COMMIT');
    return reply.status(201).send({ success: true });
  } catch (err) { await client.query('ROLLBACK'); throw err; }
  finally { client.release(); }
});

// Bon de reception ameliore : accepte supplier_id et purchase_order_id
fastify.post('/api/stock/deliveries', { onRequest: [fastify.authenticate] }, async (request, reply) => {
  const { items, reason, supplier_id, purchase_order_id } = request.body;
  const user_id = request.user.id;
  if (!Array.isArray(items) || items.length === 0) return reply.status(400).send({ error: 'Aucun produit a receptionner' });

  const batch_ref = 'BR-' + Date.now();
  let supplierName = null;
  if (supplier_id) {
    const supRes = await db.query('SELECT name FROM utiam_suppliers WHERE id = $1', [supplier_id]);
    if (supRes.rows.length > 0) supplierName = supRes.rows[0].name;
  }
  const note = supplierName ? `Fournisseur: ${supplierName}${reason ? ' - ' + reason : ''}` : (reason || null);

  const client = await db.connect();
  try {
    await client.query('BEGIN');
    for (const item of items) {
      if (!item.product_id || !item.quantity || Number(item.quantity) <= 0) continue;
      await client.query(
        'INSERT INTO utiam_stock_movements (product_id, type, quantity, reason, unit_price, batch_ref, purchase_order_id, user_id) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)',
        [item.product_id, 'delivery', Math.abs(item.quantity), note, item.unit_price || null, batch_ref, purchase_order_id || null, user_id]
      );
      await client.query('UPDATE utiam_products SET stock = stock + $1, updated_at = NOW() WHERE id = $2', [Math.abs(item.quantity), item.product_id]);

      if (supplier_id && item.unit_price) {
        const existing = await client.query('SELECT id FROM utiam_product_suppliers WHERE product_id = $1 AND supplier_id = $2', [item.product_id, supplier_id]);
        if (existing.rows.length > 0) {
          await client.query('UPDATE utiam_product_suppliers SET unit_price = $1 WHERE id = $2', [item.unit_price, existing.rows[0].id]);
        } else {
          await client.query('INSERT INTO utiam_product_suppliers (product_id, supplier_id, unit_price) VALUES ($1, $2, $3)', [item.product_id, supplier_id, item.unit_price]);
        }
      }

      if (purchase_order_id) {
        await client.query(
          'UPDATE utiam_purchase_order_items SET quantity_received = quantity_received + $1 WHERE purchase_order_id = $2 AND product_id = $3',
          [Math.abs(item.quantity), purchase_order_id, item.product_id]
        );
      }
    }

    if (purchase_order_id) {
      const itemsCheck = await client.query(
        'SELECT SUM(quantity_ordered) as ordered, SUM(quantity_received) as received FROM utiam_purchase_order_items WHERE purchase_order_id = $1',
        [purchase_order_id]
      );
      const ordered = Number(itemsCheck.rows[0].ordered);
      const received = Number(itemsCheck.rows[0].received);
      let newStatus;
      if (received >= ordered) newStatus = 'received';
      else if (received > 0) newStatus = 'partial';
      if (newStatus) {
        await client.query("UPDATE utiam_purchase_orders SET status = $1, received_at = COALESCE(received_at, NOW()) WHERE id = $2", [newStatus, purchase_order_id]);
      }
    }

    await client.query('COMMIT');
    return reply.status(201).send({ success: true, batch_ref, count: items.length });
  } catch (err) { await client.query('ROLLBACK'); throw err; }
  finally { client.release(); }
});

fastify.post('/api/stock/inventory', { onRequest: [fastify.authenticate] }, async (request, reply) => {
  const { items, reason } = request.body;
  const user_id = request.user.id;
  if (!Array.isArray(items) || items.length === 0) return reply.status(400).send({ error: 'Aucun produit dans l\'inventaire' });
  const batch_ref = 'INV-' + Date.now();
  const note = reason || 'Inventaire physique';
  const client = await db.connect();
  const adjustments = [];
  try {
    await client.query('BEGIN');
    for (const item of items) {
      if (!item.product_id) continue;
      const counted = Number(item.counted_quantity);
      if (isNaN(counted) || counted < 0) continue;
      const cur = await client.query('SELECT stock, name FROM utiam_products WHERE id = $1', [item.product_id]);
      if (cur.rows.length === 0) continue;
      const currentStock = Number(cur.rows[0].stock);
      const delta = counted - currentStock;
      if (delta === 0) continue;
      await client.query('INSERT INTO utiam_stock_movements (product_id, type, quantity, reason, batch_ref, user_id) VALUES ($1, $2, $3, $4, $5, $6)', [item.product_id, 'inventory', delta, note, batch_ref, user_id]);
      await client.query('UPDATE utiam_products SET stock = $1, updated_at = NOW() WHERE id = $2', [counted, item.product_id]);
      adjustments.push({ product_id: item.product_id, name: cur.rows[0].name, before: currentStock, after: counted, delta });
    }
    await client.query('COMMIT');
    return reply.status(201).send({ success: true, batch_ref, adjustments });
  } catch (err) { await client.query('ROLLBACK'); throw err; }
  finally { client.release(); }
});

fastify.get('/api/stock/summary', { onRequest: [fastify.authenticate] }, async () => {
  const out_of_stock = await db.query("SELECT id, name, barcode, unit FROM utiam_products WHERE stock = 0 AND status = 'active' ORDER BY name");
  const low_stock = await db.query("SELECT id, name, stock, min_stock, unit FROM utiam_products WHERE stock > 0 AND stock <= min_stock AND status = 'active' ORDER BY stock ASC");
  const expiring_soon = await db.query("SELECT id, name, expiry_date, stock, unit FROM utiam_products WHERE expiry_date IS NOT NULL AND expiry_date <= NOW() + INTERVAL '30 days' AND expiry_date >= CURRENT_DATE AND status = 'active' AND stock > 0 ORDER BY expiry_date ASC");
  const expired = await db.query("SELECT id, name, expiry_date, stock, unit FROM utiam_products WHERE expiry_date IS NOT NULL AND expiry_date < CURRENT_DATE AND status = 'active' AND stock > 0 ORDER BY expiry_date ASC");
  return { out_of_stock: out_of_stock.rows, low_stock: low_stock.rows, expiring_soon: expiring_soon.rows, expired: expired.rows };
});

// ─── RAPPORTS ─────────────────────────────────────────────
fastify.get('/api/reports/summary', { onRequest: [fastify.authenticate] }, async (request) => {
  const { from, to } = request.query;
  const dateFrom = from || new Date(new Date().setDate(1)).toISOString().split('T')[0];
  const dateTo = to || new Date().toISOString().split('T')[0];
  const revenue = await db.query(`SELECT COALESCE(SUM(total), 0) as total, COUNT(*) as count, COALESCE(AVG(total), 0) as avg_basket FROM utiam_sales WHERE created_at::date BETWEEN $1 AND $2`, [dateFrom, dateTo]);
  const topProducts = await db.query(`SELECT p.name, SUM(si.quantity) as qty, SUM(si.total) as revenue FROM utiam_sale_items si JOIN utiam_products p ON si.product_id = p.id JOIN utiam_sales s ON si.sale_id = s.id WHERE s.created_at::date BETWEEN $1 AND $2 GROUP BY p.name ORDER BY qty DESC LIMIT 10`, [dateFrom, dateTo]);
  const topClients = await db.query(`SELECT c.id, c.name, c.phone, COUNT(s.id) as visits, SUM(s.total) as revenue FROM utiam_sales s JOIN utiam_clients c ON s.client_id = c.id WHERE s.created_at::date BETWEEN $1 AND $2 AND s.client_id IS NOT NULL GROUP BY c.id, c.name, c.phone ORDER BY revenue DESC LIMIT 10`, [dateFrom, dateTo]);
  const paymentMethods = await db.query(`SELECT payment_method, COUNT(*) as count, SUM(total) as total FROM utiam_sales WHERE created_at::date BETWEEN $1 AND $2 GROUP BY payment_method ORDER BY total DESC`, [dateFrom, dateTo]);
  const hourlySales = await db.query(`SELECT EXTRACT(HOUR FROM created_at)::int as hour, COUNT(*) as count, SUM(total) as total FROM utiam_sales WHERE created_at::date BETWEEN $1 AND $2 GROUP BY EXTRACT(HOUR FROM created_at) ORDER BY hour ASC`, [dateFrom, dateTo]);
  const cashiers = await db.query(`SELECT u.id, u.display_name, u.role, COUNT(s.id) as count, SUM(s.total) as total, AVG(s.total) as avg_basket FROM utiam_sales s JOIN utiam_users u ON s.cashier_id = u.id WHERE s.created_at::date BETWEEN $1 AND $2 GROUP BY u.id, u.display_name, u.role ORDER BY total DESC`, [dateFrom, dateTo]);
  const marginResult = await db.query(`SELECT COALESCE(SUM(si.total), 0) as revenue, COALESCE(SUM(si.quantity * COALESCE(p.buy_price, 0)), 0) as cost FROM utiam_sale_items si JOIN utiam_products p ON si.product_id = p.id JOIN utiam_sales s ON si.sale_id = s.id WHERE s.created_at::date BETWEEN $1 AND $2`, [dateFrom, dateTo]);
  const margin = {
    revenue: Number(marginResult.rows[0].revenue),
    cost: Number(marginResult.rows[0].cost),
    gross: Number(marginResult.rows[0].revenue) - Number(marginResult.rows[0].cost),
    rate: Number(marginResult.rows[0].revenue) > 0 ? ((Number(marginResult.rows[0].revenue) - Number(marginResult.rows[0].cost)) / Number(marginResult.rows[0].revenue)) * 100 : 0,
  };
  const lowStock = await db.query("SELECT name, stock, min_stock FROM utiam_products WHERE stock <= min_stock AND status = 'active' ORDER BY stock ASC LIMIT 20");
  const outOfStock = await db.query("SELECT name, barcode FROM utiam_products WHERE stock = 0 AND status = 'active' ORDER BY name LIMIT 20");
  return {
    period: { from: dateFrom, to: dateTo },
    revenue: { total: Number(revenue.rows[0].total), count: Number(revenue.rows[0].count), avg_basket: Number(revenue.rows[0].avg_basket) },
    top_products: topProducts.rows, top_clients: topClients.rows, payment_methods: paymentMethods.rows,
    hourly_sales: hourlySales.rows, cashiers: cashiers.rows, margin,
    low_stock: lowStock.rows, out_of_stock: outOfStock.rows,
  };
});

fastify.get('/api/reports/stock-value', { onRequest: [fastify.authenticate] }, async () => {
  const result = await db.query(`SELECT COUNT(*) as product_count, COALESCE(SUM(stock), 0) as total_units, COALESCE(SUM(stock * COALESCE(buy_price, 0)), 0) as value_buy, COALESCE(SUM(stock * sell_price), 0) as value_sell FROM utiam_products WHERE status = 'active' AND stock > 0`);
  const row = result.rows[0];
  return {
    product_count: Number(row.product_count),
    total_units: Number(row.total_units),
    value_buy: Number(row.value_buy),
    value_sell: Number(row.value_sell),
    potential_margin: Number(row.value_sell) - Number(row.value_buy),
  };
});

// ─── UTILISATEURS ─────────────────────────────────────────
fastify.get('/api/users', { onRequest: [fastify.authenticate] }, async () => {
  const result = await db.query(`
    SELECT u.id, u.email, u.display_name, u.role, u.is_active, u.must_change_password, u.created_at,
           COALESCE(stats.sales_count, 0) as sales_count,
           COALESCE(stats.total_revenue, 0) as total_revenue,
           stats.last_sale
    FROM utiam_users u
    LEFT JOIN (
      SELECT cashier_id, COUNT(*) as sales_count, SUM(total) as total_revenue, MAX(created_at) as last_sale
      FROM utiam_sales GROUP BY cashier_id
    ) stats ON stats.cashier_id = u.id
    ORDER BY u.created_at DESC
  `);
  return result.rows;
});

fastify.post('/api/users', { onRequest: [fastify.authenticate] }, async (request, reply) => {
  if (request.user.role !== 'admin') return reply.status(403).send({ error: 'Seul un administrateur peut creer des utilisateurs' });
  const { email, password, display_name, role } = request.body;
  if (!email || !password || !display_name) return reply.status(400).send({ error: 'Email, mot de passe et nom obligatoires' });
  if (!['admin', 'gerant', 'caissier'].includes(role)) return reply.status(400).send({ error: 'Role invalide' });
  const pwdErr = validatePasswordStrength(password);
  if (pwdErr) return reply.status(400).send({ error: pwdErr });
  const existing = await db.query('SELECT id FROM utiam_users WHERE email = $1', [email]);
  if (existing.rows.length > 0) return reply.status(409).send({ error: 'Cet email est deja utilise' });
  const hash = await bcrypt.hash(password, 10);
  const result = await db.query(
    'INSERT INTO utiam_users (email, password_hash, display_name, role, must_change_password) VALUES ($1, $2, $3, $4, TRUE) RETURNING id, email, display_name, role, is_active, must_change_password',
    [email, hash, display_name, role]
  );
  return reply.status(201).send(result.rows[0]);
});

fastify.put('/api/users/:id', { onRequest: [fastify.authenticate] }, async (request, reply) => {
  if (request.user.role !== 'admin') return reply.status(403).send({ error: 'Seul un administrateur peut modifier les utilisateurs' });
  const { id } = request.params;
  const { email, display_name, role } = request.body;
  if (!email || !display_name) return reply.status(400).send({ error: 'Email et nom obligatoires' });
  if (!['admin', 'gerant', 'caissier'].includes(role)) return reply.status(400).send({ error: 'Role invalide' });
  if (role !== 'admin') {
    const userCheck = await db.query('SELECT role FROM utiam_users WHERE id = $1', [id]);
    if (userCheck.rows.length > 0 && userCheck.rows[0].role === 'admin') {
      const adminCount = await db.query("SELECT COUNT(*) as cnt FROM utiam_users WHERE role = 'admin' AND is_active = true");
      if (parseInt(adminCount.rows[0].cnt) <= 1) {
        return reply.status(409).send({ error: 'Impossible de retrograder le dernier administrateur actif' });
      }
    }
  }
  const existing = await db.query('SELECT id FROM utiam_users WHERE email = $1 AND id != $2', [email, id]);
  if (existing.rows.length > 0) return reply.status(409).send({ error: 'Cet email est deja utilise' });
  const result = await db.query('UPDATE utiam_users SET email = $1, display_name = $2, role = $3 WHERE id = $4 RETURNING id, email, display_name, role, is_active', [email, display_name, role, id]);
  if (result.rows.length === 0) return reply.status(404).send({ error: 'Utilisateur introuvable' });
  return result.rows[0];
});

fastify.put('/api/users/:id/status', { onRequest: [fastify.authenticate] }, async (request, reply) => {
  if (request.user.role !== 'admin') return reply.status(403).send({ error: 'Seul un administrateur peut modifier le statut des utilisateurs' });
  const { id } = request.params;
  const { is_active } = request.body;
  if (typeof is_active !== 'boolean') return reply.status(400).send({ error: 'is_active doit etre un booleen' });
  if (parseInt(id) === request.user.id && !is_active) return reply.status(409).send({ error: 'Vous ne pouvez pas desactiver votre propre compte' });
  if (!is_active) {
    const userCheck = await db.query('SELECT role FROM utiam_users WHERE id = $1', [id]);
    if (userCheck.rows.length > 0 && userCheck.rows[0].role === 'admin') {
      const adminCount = await db.query("SELECT COUNT(*) as cnt FROM utiam_users WHERE role = 'admin' AND is_active = true");
      if (parseInt(adminCount.rows[0].cnt) <= 1) {
        return reply.status(409).send({ error: 'Impossible de desactiver le dernier administrateur actif' });
      }
    }
  }
  const result = await db.query('UPDATE utiam_users SET is_active = $1 WHERE id = $2 RETURNING id, email, display_name, role, is_active', [is_active, id]);
  if (result.rows.length === 0) return reply.status(404).send({ error: 'Utilisateur introuvable' });
  return result.rows[0];
});

fastify.post('/api/users/:id/reset-password', { onRequest: [fastify.authenticate] }, async (request, reply) => {
  if (request.user.role !== 'admin') return reply.status(403).send({ error: 'Seul un administrateur peut reinitialiser les mots de passe' });
  const { id } = request.params;
  const { new_password } = request.body;
  const pwdErr = validatePasswordStrength(new_password);
  if (pwdErr) return reply.status(400).send({ error: pwdErr });
  const hash = await bcrypt.hash(new_password, 10);
  const result = await db.query('UPDATE utiam_users SET password_hash = $1, must_change_password = TRUE WHERE id = $2 RETURNING id', [hash, id]);
  if (result.rows.length === 0) return reply.status(404).send({ error: 'Utilisateur introuvable' });
  return { success: true };
});

fastify.put('/api/users/me/password', { onRequest: [fastify.authenticate] }, async (request, reply) => {
  const { current_password, new_password } = request.body;
  if (!new_password) return reply.status(400).send({ error: 'Nouveau mot de passe requis' });
  const pwdErr = validatePasswordStrength(new_password);
  if (pwdErr) return reply.status(400).send({ error: pwdErr });
  const userRes = await db.query('SELECT password_hash, must_change_password FROM utiam_users WHERE id = $1', [request.user.id]);
  if (userRes.rows.length === 0) return reply.status(404).send({ error: 'Utilisateur introuvable' });
  const user = userRes.rows[0];
  if (!user.must_change_password) {
    if (!current_password) return reply.status(400).send({ error: 'Mot de passe actuel requis' });
    const valid = await bcrypt.compare(current_password, user.password_hash);
    if (!valid) return reply.status(401).send({ error: 'Mot de passe actuel incorrect' });
  }
  const same = await bcrypt.compare(new_password, user.password_hash);
  if (same) return reply.status(400).send({ error: 'Le nouveau mot de passe doit etre different de l\'ancien' });
  const newHash = await bcrypt.hash(new_password, 10);
  await db.query('UPDATE utiam_users SET password_hash = $1, must_change_password = FALSE WHERE id = $2', [newHash, request.user.id]);
  return { success: true };
});

// ─── DEMARRAGE ────────────────────────────────────────────
const start = async () => {
  try {
    await fastify.listen({ port: 3002, host: '0.0.0.0' });
    console.log('U TIAM backend demarre sur le port 3002');
  } catch (err) {
    fastify.log.error(err);
    process.exit(1);
  }
};

start();
