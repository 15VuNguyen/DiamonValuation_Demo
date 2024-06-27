import { defineConfig } from "vite";
import react from "@vitejs/plugin-react-swc";

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  css: {
    devSourcemap: true, //debug báo lỗi ở dòng nào cụ thể
  },
  server: {
    port: 3000,
  },
});
