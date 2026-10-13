import axios from "axios";

const api = axios.create({ baseURL: "/api/v1" });

export async function fetchItems() {
  const res = await api.get("/items");
  return res.data;
}
