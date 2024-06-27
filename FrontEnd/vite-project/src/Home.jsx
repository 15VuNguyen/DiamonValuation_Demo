import reactLogo from "./assets/react.svg";
import viteLogo from "/vite.svg";
import "./App.css";
import { Link } from "react-router-dom";
export default function Home() {
  const isAuthenticated = localStorage.getItem("accessToken"); //kiểm tra xem đã có access token hay chưa
  const logout = () => {
    localStorage.removeItem("accessToken"); //xóa access token trong localStorage
    localStorage.removeItem("refreshToken"); //xóa refresh token trong localStorage
    window.location.reload(); //reload lại trang
  };

  const getGoogleAuthUrl = () => {
    const { VITE_GOOGLE_CLIENT_ID, VITE_GOOGLE_REDIRECT_URI } = import.meta.env; //import vào .env của Vite
    const url = "https://accounts.google.com/o/oauth2/v2/auth";
    const query = {
      client_id: VITE_GOOGLE_CLIENT_ID,
      redirect_uri: VITE_GOOGLE_REDIRECT_URI,
      response_type: "code",
      scope: [
        "https://www.googleapis.com/auth/userinfo.email",
        "https://www.googleapis.com/auth/userinfo.profile",
      ].join(" "), //các quyền truy cập, và chuyển thành chuỗi cách nhau bằng space
      prompt: "consent", //nhắc người dùng đồng ý cho phép truy cập
      access_type: "offline", //truy cập offline giúp lấy thêm refresh token
    };
    return `${url}?${new URLSearchParams(query)}`; //URLSearchParams(hàm có sẵn): tạo ra chuỗi query dạng key=value&key=value để làm query string
  };

  const googleAuthUrl = getGoogleAuthUrl();

  return (
    <>
      <div>
        <a href="https://vitejs.dev">
          <img src={viteLogo} className="logo" alt="Vite logo" />
        </a>
        <a href="https://react.dev">
          <img src={reactLogo} className="logo react" alt="React logo" />
        </a>
      </div>

      <h1>Google OAuth 2.0</h1>

      <p className="read-the-docs">
        {isAuthenticated ? (
          <>
            <span>Hello, you are logged in</span>
            <button onClick={logout}>Logout</button>
          </>
        ) : (
          <Link to={googleAuthUrl}>Login with Google</Link>
        )}
      </p>
    </>
  );
}
