import axios from "axios";

const api = axios.create({
  baseURL: "https://nldc-loganalyzer.onrender.com",
  headers: {
    "Content-Type": "application/json",
  },
});

export default api;
