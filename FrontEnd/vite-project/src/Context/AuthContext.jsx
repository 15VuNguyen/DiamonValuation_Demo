import auth from "../../FireBase/config";
import { useState, useContext, createContext, useEffect } from "react";
import { signInWithEmailAndPassword, GoogleAuthProvider, signInWithPopup, onAuthStateChanged, signOut } from "firebase/auth";


const AuthContext = createContext();


export function useAuth() {
  return useContext(AuthContext);
}

export function AuthProvider({ children }) {
  const [currentUser, setCurrentUser] = useState(null);
  const [loading, setLoading] = useState(true);

  const signIn = async (email, password) => {
    return signInWithEmailAndPassword(auth, email, password);
  };

  // Function to sign in with Google
  const signInWithGoogle = async () => {
    const provider = new GoogleAuthProvider();
    return signInWithPopup(auth, provider);
  };

  // Function to sign out
  const signOutUser = async () => {
    return signOut(auth);
  };

  // Set up an effect to handle authentication state changes
  useEffect(() => {
    const unsubscribe = onAuthStateChanged(auth, async (user) => {
      setCurrentUser(user);
      if (user) {
        const jwt = await user.getIdToken();
        localStorage.setItem("token", jwt);
      } else {
        localStorage.removeItem("token");
      }
      setLoading(false);
    });

    return unsubscribe;
  }, []);

  // Provide the authentication state and functions to children components
  const value = {
    currentUser,
    signIn,
    signInWithGoogle,
    signOutUser,
  };

  return (
    <AuthContext.Provider value={value}>
      {!loading && children}
    </AuthContext.Provider>
  );
}
