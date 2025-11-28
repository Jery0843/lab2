"use client";

import * as React from "react";
import { FaSun, FaMoon } from "react-icons/fa";
import { useTheme } from "./ThemeProvider";

export function ThemeToggle() {
  const { theme, setTheme } = useTheme();

  return (
    <button
      onClick={() => setTheme(theme === "light" ? "dark" : "light")}
      className="relative inline-flex items-center justify-center rounded-md p-2 hover:bg-card-bg/50 focus:outline-none focus:ring-2 focus:ring-cyber-green focus:ring-offset-2 transition-all duration-300"
      title={`Switch to ${theme === "light" ? "dark" : "light"} mode`}
    >
      <span className="sr-only">Toggle theme</span>
      {theme === "dark" ? (
        <FaSun className="h-5 w-5 text-cyber-green hover:text-cyber-pink transition-colors duration-300" />
      ) : (
        <FaMoon className="h-5 w-5 text-cyber-green hover:text-cyber-pink transition-colors duration-300" />
      )}
    </button>
  );
}
