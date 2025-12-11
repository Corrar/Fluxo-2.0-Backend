import { Pool } from 'pg';
import dotenv from 'dotenv';

dotenv.config();

// Se o seu código estiver sendo executado em um ambiente que usa o arquivo .env
// e não em um ambiente de produção (onde as variáveis de ambiente são injetadas
// diretamente), essa linha garante que o NODE_ENV seja lido.

// Lógica para determinar se estamos em ambiente de produção (online)
const isProduction = process.env.NODE_ENV === 'production';

export const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  
  // Condição para ativar o SSL:
  // Em produção, o SSL deve ser ativado, geralmente com 'rejectUnauthorized: false'
  // para provedores como Render, Heroku ou Railway, que usam certificado próprio.
  ssl: isProduction ? { rejectUnauthorized: false } : false,
});