import express from 'express';
import cors from 'cors';
import { pool } from './db';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

const app = express();
app.use(cors());
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET || 'sua-chave-secreta';

// --- MIDDLEWARE DE AUTENTICAÇÃO ---
const authenticate = (req: any, res: any, next: any) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'Token necessário' });

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ error: 'Token inválido' });
  }
};

// ==========================================
// AUTENTICAÇÃO E USUÁRIOS
// ==========================================

app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const { rows } = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    const user = rows[0];

    if (!user) return res.status(400).json({ error: 'Usuário não encontrado' });

    const validPassword = await bcrypt.compare(password, user.encrypted_password);
    if (!validPassword) return res.status(400).json({ error: 'Senha incorreta' });

    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '1d' });
    
    // Auto-Cura de Perfil
    let { rows: profiles } = await pool.query('SELECT * FROM profiles WHERE id = $1', [user.id]);
    if (profiles.length === 0) {
      const defaultName = user.email.split('@')[0];
      const insertRes = await pool.query(
        `INSERT INTO profiles (id, name, role, sector) VALUES ($1, $2, 'setor', 'Geral') RETURNING *`,
        [user.id, defaultName]
      );
      profiles = insertRes.rows;
    }
    
    res.json({ token, user, profile: profiles[0] });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/auth/register', async (req, res) => {
  const { email, password, name, role, sector } = req.body;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const userCheck = await client.query('SELECT id FROM users WHERE email = $1', [email]);
    if (userCheck.rows.length > 0) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'ID de usuário já está em uso' });
    }
    const salt = await bcrypt.genSalt(10);
    const encryptedPassword = await bcrypt.hash(password, salt);
    
    const userRes = await client.query(
      'INSERT INTO users (email, encrypted_password) VALUES ($1, $2) RETURNING id',
      [email, encryptedPassword]
    );
    const newUserId = userRes.rows[0].id;

    await client.query(
      `INSERT INTO profiles (id, name, role, sector) VALUES ($1, $2, $3, $4)
       ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, role = EXCLUDED.role, sector = EXCLUDED.sector`,
      [newUserId, name, role, sector]
    );

    await client.query('COMMIT');
    res.status(201).json({ success: true });
  } catch (error: any) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: error.message });
  } finally {
    client.release();
  }
});

app.get('/users', authenticate, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT u.id, u.email, COALESCE(p.name, u.email) as name, COALESCE(p.role, 'setor') as role, COALESCE(p.sector, '-') as sector, u.created_at
      FROM users u LEFT JOIN profiles p ON u.id = p.id ORDER BY u.created_at DESC
    `);
    res.json(rows);
  } catch (error: any) {
    res.status(500).json({ error: 'Erro ao buscar usuários' });
  }
});

app.put('/users/:id/role', authenticate, async (req, res) => {
  const { id } = req.params;
  const { role } = req.body;
  try {
    await pool.query('UPDATE profiles SET role = $1 WHERE id = $2', [role, id]);
    res.json({ success: true });
  } catch (error: any) {
    res.status(500).json({ error: 'Erro ao atualizar função' });
  }
});

app.delete('/users/:id', authenticate, async (req, res) => {
  const { id } = req.params;
  try {
    await pool.query('DELETE FROM users WHERE id = $1', [id]);
    res.json({ success: true });
  } catch (error: any) {
    res.status(500).json({ error: 'Erro ao excluir usuário' });
  }
});

// ==========================================
// PRODUTOS
// ==========================================

app.get('/products', authenticate, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT p.*, COALESCE(json_agg(s.*) FILTER (WHERE s.id IS NOT NULL), '[]') as stock 
      FROM products p 
      LEFT JOIN stock s ON p.id = s.product_id 
      WHERE p.active = true 
      GROUP BY p.id 
      ORDER BY p.created_at DESC
    `);
    res.json(rows);
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/products/low-stock', authenticate, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT 
        p.id, p.sku, p.name, p.unit, p.min_stock, 
        p.purchase_status, p.purchase_note, p.delivery_forecast,
        COALESCE(s.quantity_on_hand, 0) as quantity_on_hand, 
        COALESCE(s.quantity_reserved, 0) as quantity_reserved, 
        (COALESCE(s.quantity_on_hand, 0) - COALESCE(s.quantity_reserved, 0)) as disponivel,
        (
          SELECT COALESCE(SUM(ri.quantity_requested), 0)
          FROM request_items ri
          JOIN requests r ON ri.request_id = r.id
          WHERE ri.product_id = p.id AND r.status IN ('aberto', 'aprovado')
        ) as demanda_reprimida
      FROM products p
      LEFT JOIN stock s ON p.id = s.product_id
      WHERE p.min_stock IS NOT NULL 
        AND (COALESCE(s.quantity_on_hand, 0) - COALESCE(s.quantity_reserved, 0)) < p.min_stock 
        AND p.active = true
      ORDER BY (COALESCE(s.quantity_on_hand, 0) - COALESCE(s.quantity_reserved, 0)) ASC
    `);
    res.json(rows);
  } catch (error: any) { 
    console.error(error);
    res.status(500).json({ error: 'Erro low stock' }); 
  }
});

app.post('/products', authenticate, async (req, res) => {
  const { sku, name, description, unit, min_stock, quantity, unit_price, sales_price } = req.body;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    
    const productRes = await client.query(
      'INSERT INTO products (sku, name, description, unit, min_stock, unit_price, sales_price) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *',
      [sku, name, description, unit, min_stock, unit_price || 0, sales_price || 0]
    );
    const newProduct = productRes.rows[0];

    const initialQty = quantity ? parseFloat(quantity) : 0;
    await client.query(
      `INSERT INTO stock (product_id, quantity_on_hand, quantity_reserved) 
       VALUES ($1, $2, 0)
       ON CONFLICT (product_id) 
       DO UPDATE SET quantity_on_hand = COALESCE(stock.quantity_on_hand, 0) + EXCLUDED.quantity_on_hand`,
      [newProduct.id, initialQty]
    );

    if (initialQty > 0) {
      const logRes = await client.query("INSERT INTO xml_logs (file_name, success, total_items) VALUES ($1, $2, $3) RETURNING id", ['Estoque Inicial - Cadastro', true, 1]);
      await client.query("INSERT INTO xml_items (xml_log_id, product_id, quantity) VALUES ($1, $2, $3)", [logRes.rows[0].id, newProduct.id, initialQty]);
    }
    
    await client.query('COMMIT');
    res.status(201).json(newProduct);
  } catch (error: any) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: error.message });
  } finally {
    client.release();
  }
});

app.put('/products/:id', authenticate, async (req, res) => {
  const { id } = req.params;
  const { sku, name, description, unit, min_stock, quantity, unit_price, sales_price } = req.body;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    
    const { rows } = await client.query(
      `UPDATE products SET 
          sku = COALESCE($1, sku), 
          name = COALESCE($2, name), 
          description = COALESCE($3, description), 
          unit = COALESCE($4, unit), 
          min_stock = COALESCE($5, min_stock),
          unit_price = COALESCE($6, unit_price),
          sales_price = COALESCE($7, sales_price)
       WHERE id = $8 RETURNING *`,
      [sku || null, name || null, description || null, unit || null, min_stock || null, unit_price || null, sales_price || null, id]
    );

    if (rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Produto não encontrado' });
    }
    
    if (quantity !== undefined && quantity !== "") {
      await client.query('UPDATE stock SET quantity_on_hand = $1 WHERE product_id = $2', [parseFloat(quantity), id]);
    }
    
    await client.query('COMMIT');
    res.json(rows[0]);
  } catch (error: any) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: error.message });
  } finally {
    client.release();
  }
});

app.put('/products/:id/purchase-info', authenticate, async (req, res) => {
  const { id } = req.params;
  const { purchase_status, purchase_note, delivery_forecast } = req.body;
  try {
    await pool.query(
      'UPDATE products SET purchase_status = $1, purchase_note = $2, delivery_forecast = $3 WHERE id = $4',
      [purchase_status, purchase_note, delivery_forecast || null, id]
    );
    res.json({ success: true });
  } catch (error: any) {
    try {
        await pool.query(
            'UPDATE products SET purchase_status = $1, purchase_note = $2 WHERE id = $3',
            [purchase_status, purchase_note, id]
        );
        res.json({ success: true, warning: "Data não salva (coluna delivery_forecast pode não existir)" });
    } catch (err) {
        res.status(500).json({ error: 'Erro ao atualizar informações de compra' });
    }
  }
});

app.delete('/products/:id', authenticate, async (req, res) => {
  const { id } = req.params;
  try {
    await pool.query('UPDATE products SET active = false WHERE id = $1', [id]);
    res.json({ message: 'Produto arquivado com sucesso' });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

// --- ESTOQUE & MOVIMENTAÇÕES MANUAIS ---

app.get('/stock', authenticate, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT s.*, json_build_object('id', p.id, 'name', p.name, 'sku', p.sku, 'unit', p.unit, 'min_stock', p.min_stock, 'unit_price', p.unit_price, 'sales_price', p.sales_price) as products 
      FROM stock s JOIN products p ON s.product_id = p.id 
      WHERE p.active = true
      ORDER BY s.created_at DESC
    `);
    res.json(rows);
  } catch (error: any) {
    res.status(500).json({ error: 'Erro ao buscar estoque' });
  }
});

app.put('/stock/:id', authenticate, async (req, res) => {
  const { id } = req.params;
  const { quantity_on_hand } = req.body;
  try {
    await pool.query('UPDATE stock SET quantity_on_hand = $1 WHERE id = $2', [quantity_on_hand, id]);
    res.json({ success: true });
  } catch (error: any) {
    res.status(500).json({ error: 'Erro ao ajustar estoque' });
  }
});

// CORREÇÃO: Validação de itens na Entrada Manual
app.post('/manual-entry', authenticate, async (req, res) => {
  const { items } = req.body;
  const client = await pool.connect();
  try {
    if (!items || !Array.isArray(items) || items.length === 0) {
      return res.status(400).json({ error: "Nenhum item enviado para entrada." });
    }

    await client.query('BEGIN');
    const logRes = await client.query("INSERT INTO xml_logs (file_name, success, total_items) VALUES ($1, $2, $3) RETURNING id", [`Entrada Manual - ${new Date().toLocaleDateString('pt-BR')}`, true, items.length]);
    const logId = logRes.rows[0].id;
    
    for (const item of items) {
      if (!item.product_id || !item.quantity) throw new Error("Item inválido na lista.");
      
      await client.query("INSERT INTO xml_items (xml_log_id, product_id, quantity) VALUES ($1, $2, $3)", [logId, item.product_id, item.quantity]);
      await client.query("UPDATE stock SET quantity_on_hand = quantity_on_hand + $1 WHERE product_id = $2", [item.quantity, item.product_id]);
    }
    await client.query('COMMIT');
    res.status(201).json({ success: true });
  } catch (error: any) {
    await client.query('ROLLBACK');
    console.error("Erro na entrada manual:", error);
    res.status(500).json({ error: error.message || "Erro ao processar entrada" });
  } finally {
    client.release();
  }
});

// CORREÇÃO: Validação de itens na Saída Manual
app.post('/manual-withdrawal', authenticate, async (req, res) => {
  const { sector, items } = req.body;
  const client = await pool.connect();
  try {
    if (!items || !Array.isArray(items) || items.length === 0) {
      return res.status(400).json({ error: "Nenhum item enviado para retirada." });
    }

    await client.query('BEGIN');
    const sepRes = await client.query('INSERT INTO separations (destination, status, type) VALUES ($1, $2, $3) RETURNING id', [sector, 'concluida', 'manual']);
    const separationId = sepRes.rows[0].id;
    
    for (const item of items) {
      if (!item.product_id || !item.quantity) throw new Error("Item inválido na lista.");

      await client.query('INSERT INTO separation_items (separation_id, product_id, quantity) VALUES ($1, $2, $3)', [separationId, item.product_id, item.quantity]);
      await client.query('UPDATE stock SET quantity_on_hand = quantity_on_hand - $1 WHERE product_id = $2', [item.quantity, item.product_id]);
    }
    
    await client.query('COMMIT');
    res.status(201).json({ success: true });
  } catch (error: any) {
    await client.query('ROLLBACK');
    console.error("Erro na saída manual:", error);
    res.status(500).json({ error: error.message || "Erro ao processar saída" });
  } finally {
    client.release();
  }
});

// --- SOLICITAÇÕES (REQUESTS) ---

app.get('/requests', authenticate, async (req, res) => {
  try {
    const query = `
      SELECT r.*, json_build_object('name', p.name, 'sector', p.sector) as requester,
      (SELECT json_agg(json_build_object('id', ri.id, 'quantity_requested', ri.quantity_requested, 'custom_product_name', ri.custom_product_name, 'products', CASE WHEN pr.id IS NOT NULL THEN json_build_object('name', pr.name, 'sku', pr.sku, 'unit', pr.unit) ELSE NULL END))
       FROM request_items ri LEFT JOIN products pr ON ri.product_id = pr.id WHERE ri.request_id = r.id) as request_items
      FROM requests r LEFT JOIN profiles p ON r.requester_id = p.id ORDER BY r.created_at DESC
    `;
    const { rows } = await pool.query(query);
    res.json(rows);
  } catch (error: any) {
    res.status(500).json({ error: 'Erro ao buscar solicitações' });
  }
});

app.get('/my-requests', authenticate, async (req, res) => {
  const userId = (req as any).user.id;
  try {
    const query = `
      SELECT r.*, (SELECT json_agg(json_build_object('id', ri.id, 'quantity_requested', ri.quantity_requested, 'custom_product_name', ri.custom_product_name, 'products', CASE WHEN pr.id IS NOT NULL THEN json_build_object('name', pr.name, 'sku', pr.sku, 'unit', pr.unit) ELSE NULL END))
       FROM request_items ri LEFT JOIN products pr ON ri.product_id = pr.id WHERE ri.request_id = r.id) as request_items
      FROM requests r WHERE r.requester_id = $1 ORDER BY r.created_at DESC
    `;
    const { rows } = await pool.query(query, [userId]);
    res.json(rows);
  } catch (error: any) {
    res.status(500).json({ error: 'Erro ao buscar minhas solicitações' });
  }
});

app.post('/requests', authenticate, async (req, res) => {
  const userId = (req as any).user.id;
  const { sector, items } = req.body;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const reqRes = await client.query('INSERT INTO requests (requester_id, sector, status) VALUES ($1, $2, $3) RETURNING id', [userId, sector, 'aberto']);
    const requestId = reqRes.rows[0].id;
    for (const item of items) {
      const isCustom = item.product_id === 'custom' || !item.product_id;
      const productId = isCustom ? null : item.product_id;
      const customName = isCustom ? item.custom_name : null;
      await client.query('INSERT INTO request_items (request_id, product_id, custom_product_name, quantity_requested) VALUES ($1, $2, $3, $4)', [requestId, productId, customName, item.quantity]);
    }
    await client.query('COMMIT');
    res.status(201).json({ success: true });
  } catch (error: any) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: 'Erro ao criar solicitação' });
  } finally {
    client.release();
  }
});

app.put('/requests/:id/status', authenticate, async (req, res) => {
  const { id } = req.params;
  const { status, rejection_reason } = req.body;
  const client = await pool.connect();
  
  try {
    await client.query('BEGIN');
    const currentRes = await client.query('SELECT status FROM requests WHERE id = $1', [id]);
    const currentStatus = currentRes.rows[0]?.status;

    if (status === 'entregue' && currentStatus !== 'entregue') {
      const itemsRes = await client.query('SELECT product_id, quantity_requested FROM request_items WHERE request_id = $1', [id]);
      
      for (const item of itemsRes.rows) {
        if (item.product_id) {
          const stockCheck = await client.query('SELECT quantity_on_hand FROM stock WHERE product_id = $1', [item.product_id]);
          const currentStock = parseFloat(stockCheck.rows[0]?.quantity_on_hand || 0);
          
          if (currentStock < item.quantity_requested) {
            throw new Error(`Estoque insuficiente para realizar a entrega do produto ID: ${item.product_id}`);
          }

          await client.query(
            'UPDATE stock SET quantity_on_hand = quantity_on_hand - $1 WHERE product_id = $2', 
            [item.quantity_requested, item.product_id]
          );
        }
      }
    }

    await client.query(
      'UPDATE requests SET status = $1, rejection_reason = $2 WHERE id = $3', 
      [status, rejection_reason || null, id]
    );
    
    await client.query('COMMIT');
    res.json({ success: true });

  } catch (error: any) {
    await client.query('ROLLBACK');
    const statusCode = error.message.includes('Estoque insuficiente') ? 400 : 500;
    res.status(statusCode).json({ error: error.message || 'Erro ao atualizar status' });
  } finally {
    client.release();
  }
});

app.delete('/requests/:id', authenticate, async (req, res) => {
  const { id } = req.params;
  try {
    await pool.query('DELETE FROM requests WHERE id = $1', [id]);
    res.json({ success: true });
  } catch (error: any) {
    res.status(500).json({ error: 'Erro ao excluir solicitação' });
  }
});

// --- SEPARAÇÕES ---

app.get('/separations', authenticate, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT s.*, 
      (SELECT json_agg(json_build_object('id', si.id, 'quantity', si.quantity, 'product_id', si.product_id, 'products', json_build_object('name', p.name, 'sku', p.sku, 'unit', p.unit)))
       FROM separation_items si JOIN products p ON si.product_id = p.id WHERE si.separation_id = s.id) as separation_items
      FROM separations s 
      WHERE s.type = 'default' 
      ORDER BY s.created_at DESC
    `);
    res.json(rows);
  } catch (error: any) {
    res.status(500).json({ error: 'Erro ao buscar separações' });
  }
});

app.post('/separations', authenticate, async (req, res) => {
  const { destination, items } = req.body;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const sepRes = await client.query('INSERT INTO separations (destination, status, type) VALUES ($1, $2, $3) RETURNING id', [destination, 'pendente', 'default']);
    const separationId = sepRes.rows[0].id;
    for (const item of items) {
      await client.query('INSERT INTO separation_items (separation_id, product_id, quantity) VALUES ($1, $2, $3)', [separationId, item.product_id, item.quantity]);
      await client.query('UPDATE stock SET quantity_reserved = quantity_reserved + $1 WHERE product_id = $2', [item.quantity, item.product_id]);
    }
    await client.query('COMMIT');
    res.status(201).json({ success: true });
  } catch (error: any) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: 'Erro ao criar separação' });
  } finally {
    client.release();
  }
});

app.put('/separations/:id/status', authenticate, async (req, res) => {
  const { id } = req.params;
  const { status } = req.body;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const currentRes = await client.query('SELECT status FROM separations WHERE id = $1', [id]);
    if (status === 'concluida' && currentRes.rows[0]?.status !== 'concluida') {
      const itemsRes = await client.query('SELECT product_id, quantity FROM separation_items WHERE separation_id = $1', [id]);
      for (const item of itemsRes.rows) {
        await client.query(`UPDATE stock SET quantity_on_hand = quantity_on_hand - $1, quantity_reserved = quantity_reserved - $1 WHERE product_id = $2`, [item.quantity, item.product_id]);
      }
    }
    await client.query('UPDATE separations SET status = $1 WHERE id = $2', [status, id]);
    await client.query('COMMIT');
    res.json({ success: true });
  } catch (error: any) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: 'Erro ao atualizar separação' });
  } finally {
    client.release();
  }
});

// --- DASHBOARD & RELATÓRIOS ---

app.get('/dashboard/stats', authenticate, async (req, res) => {
  try {
    const productsRes = await pool.query('SELECT COUNT(*) FROM products WHERE active = true');
    
    // Contagem de estoque baixo CORRIGIDA para considerar produtos sem estoque (LEFT JOIN)
    const lowStockRes = await pool.query(`
      SELECT COUNT(*) 
      FROM products p
      LEFT JOIN stock s ON p.id = s.product_id
      WHERE p.min_stock IS NOT NULL 
        AND (COALESCE(s.quantity_on_hand, 0) - COALESCE(s.quantity_reserved, 0)) < p.min_stock 
        AND p.active = true
    `);
    
    const requestsRes = await pool.query('SELECT COUNT(*) FROM requests');
    const openRequestsRes = await pool.query("SELECT COUNT(*) FROM requests WHERE status = 'aberto'");
    const separationsRes = await pool.query("SELECT COUNT(*) FROM separations WHERE type = 'default'");
    
    // --- CÁLCULO FINANCEIRO ROBUSTO ---
    const stockItemsRes = await pool.query(`
      SELECT s.quantity_on_hand, p.unit_price, p.name
      FROM stock s 
      JOIN products p ON s.product_id = p.id 
      WHERE p.active = true
    `);

    let totalValueCalculated = 0;
    
    stockItemsRes.rows.forEach((item: any) => {
        const qtd = parseFloat(item.quantity_on_hand);
        const preco = parseFloat(item.unit_price);

        if (!isNaN(qtd) && !isNaN(preco)) {
            const subtotal = qtd * preco;
            totalValueCalculated += subtotal;
        }
    });

    console.log(`[DEBUG DASHBOARD] Valor Total Calculado: ${totalValueCalculated}`);
    
    res.json({
      totalProducts: parseInt(productsRes.rows[0].count),
      lowStock: parseInt(lowStockRes.rows[0].count),
      totalRequests: parseInt(requestsRes.rows[0].count),
      openRequests: parseInt(openRequestsRes.rows[0].count),
      totalSeparations: parseInt(separationsRes.rows[0].count),
      totalValue: totalValueCalculated,
    });
  } catch (error: any) { 
    console.error("Erro no Dashboard Stats:", error);
    res.status(500).json({ error: 'Erro ao carregar estatísticas' }); 
  }
});

app.get('/reports/available-dates', authenticate, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT MIN(data) as min_date, MAX(data) as max_date FROM (
        SELECT created_at as data FROM xml_items
        UNION ALL
        SELECT created_at as data FROM separations WHERE status = 'concluida'
        UNION ALL
        SELECT created_at as data FROM requests WHERE status IN ('aprovado', 'entregue')
      ) as all_dates
    `);
    res.json(result.rows[0]);
  } catch (error: any) { res.status(500).json({ error: 'Erro dates' }); }
});

app.get('/reports/general', authenticate, async (req, res) => {
  const { startDate, endDate } = req.query;
  if (!startDate || !endDate) return res.status(400).json({ error: 'Datas obrigatórias' });
  
  const start = `${startDate} 00:00:00`;
  const end = `${endDate} 23:59:59`;

  try {
    const entradasRes = await pool.query(`
      SELECT xi.created_at as data, 'Entrada' as tipo, xl.file_name as origem, p.name as produto, p.sku, p.unit as unidade, xi.quantity as quantidade
      FROM xml_items xi JOIN products p ON xi.product_id = p.id JOIN xml_logs xl ON xi.xml_log_id = xl.id
      WHERE xi.created_at >= $1 AND xi.created_at <= $2 ORDER BY xi.created_at DESC
    `, [start, end]);

    const separacoesRes = await pool.query(`
      SELECT s.created_at as data, CASE WHEN s.type='manual' THEN 'Saída - Manual' ELSE 'Saída - Separação' END as tipo, s.destination as destino_setor, p.name as produto, p.sku, p.unit as unidade, si.quantity as quantidade
      FROM separation_items si JOIN separations s ON si.separation_id = s.id JOIN products p ON si.product_id = p.id
      WHERE s.created_at >= $1 AND s.created_at <= $2 AND s.status = 'concluida' ORDER BY s.created_at DESC
    `, [start, end]);

    const solicitacoesRes = await pool.query(`
      SELECT r.created_at as data, 'Saída - Solicitação' as tipo, COALESCE(pf.sector, r.sector) as destino_setor, pf.name as solicitante, COALESCE(p.name, ri.custom_product_name) as produto, p.sku, p.unit as unidade, ri.quantity_requested as quantidade, r.status
      FROM request_items ri JOIN requests r ON ri.request_id = r.id LEFT JOIN products p ON ri.product_id = p.id LEFT JOIN profiles pf ON r.requester_id = pf.id
      WHERE r.created_at >= $1 AND r.created_at <= $2 AND r.status IN ('aprovado', 'entregue') ORDER BY r.created_at DESC
    `, [start, end]);

    res.json({
      entradas: entradasRes.rows,
      saidas_separacoes: separacoesRes.rows,
      saidas_solicitacoes: solicitacoesRes.rows
    });
  } catch (error: any) {
    res.status(500).json({ error: 'Erro ao gerar relatório' });
  }
});

// ==========================================
// CÁLCULO DE ESTOQUE MÍNIMO
// ==========================================
app.post('/stock/calculate-min', authenticate, async (req, res) => {
  const { days } = req.body;
  const period = Number(days);

  if (!period || period < 7 || period > 365) {
    return res.status(400).json({ error: 'Período inválido' });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - period);
    
    const consumptionQuery = `
      SELECT 
        si.product_id, 
        SUM(si.quantity) as total_consumed
      FROM separation_items si
      JOIN separations s ON si.separation_id = s.id
      WHERE s.status = 'concluida' 
      AND s.created_at >= $1
      GROUP BY si.product_id
    `;
    
    const { rows: consumptionData } = await client.query(consumptionQuery, [cutoffDate]);
    let updatedCount = 0;

    for (const item of consumptionData) {
      const total = parseFloat(item.total_consumed);
      const avgDaily = total / period;
      const newMinStock = Math.ceil(avgDaily * 7);

      if (newMinStock > 0) {
        await client.query(
          'UPDATE products SET min_stock = $1 WHERE id = $2',
          [newMinStock, item.product_id]
        );
        updatedCount++;
      }
    }

    await client.query('COMMIT');
    res.json({ 
      success: true, 
      message: `Cálculo concluído. ${updatedCount} produtos atualizados.` 
    });

  } catch (error: any) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: error.message });
  } finally {
    client.release();
  }
});

// --- FUNÇÕES PRO DE ADMIN ---

app.post('/users/heartbeat', authenticate, async (req, res) => {
  const userId = (req as any).user.id;
  try {
    await pool.query(`
      UPDATE profiles 
      SET total_minutes = COALESCE(total_minutes, 0) + 1,
          last_active = NOW()
      WHERE id = $1
    `, [userId]);
    res.json({ success: true });
  } catch (error) {
    res.json({ success: false }); 
  }
});

app.post('/admin/reset-password', authenticate, async (req, res) => {
  const { userId, newPassword } = req.body;
  const requesterId = (req as any).user.id;
  const adminCheck = await pool.query("SELECT role FROM profiles WHERE id = $1", [requesterId]);
  
  if (adminCheck.rows[0]?.role !== 'admin') {
    return res.status(403).json({ error: 'Apenas administradores podem resetar senhas.' });
  }

  try {
    const salt = await bcrypt.genSalt(10);
    const encryptedPassword = await bcrypt.hash(newPassword, salt);

    await pool.query('UPDATE users SET encrypted_password = $1 WHERE id = $2', [encryptedPassword, userId]);
    res.json({ success: true, message: 'Senha redefinida com sucesso.' });
  } catch (error: any) {
    res.status(500).json({ error: 'Erro ao resetar senha.' });
  }
});

// Usa a porta definida pelo servidor ou 3000 se for local
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server rodando na porta ${PORT}`));