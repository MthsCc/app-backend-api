import { MongoClient } from "mongodb";
import bcrypt from "bcrypt";
import dotenv from "dotenv";

dotenv.config();

const uri = process.env.DATABASE_URL; // sua string de conexão MongoDB
const client = new MongoClient(uri);

async function fixUsers() {
  try {
    await client.connect();
    const db = client.db("Users"); // substitua pelo nome do seu DB
    const collection = db.collection("User"); // nome da coleção

    // Buscar usuários sem password ou com password nulo
    const users = await collection.find({
      $or: [
        { password: null },
        { password: { $exists: false } }
      ]
    }).toArray();

    if (users.length === 0) {
      console.log("Todos os usuários já têm senha.");
      return;
    }

    console.log(`Encontrados ${users.length} usuários sem senha. Corrigindo...`);

    for (const user of users) {
      const tempPassword = "temporaria123"; // senha provisória
      const hashedPassword = await bcrypt.hash(tempPassword, 10);

      await collection.updateOne(
        { _id: user._id },
        { $set: { password: hashedPassword } }
      );

      console.log(`Usuário ${user.email} atualizado com senha temporária: ${tempPassword}`);
    }

    console.log("Todos os usuários foram corrigidos com sucesso!");
  } catch (error) {
    console.error("Erro ao corrigir usuários:", error);
  } finally {
    await client.close();
  }
}

fixUsers();
