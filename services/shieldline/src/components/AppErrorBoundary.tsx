import { Component, type ErrorInfo, type ReactNode } from "react";
import { AlertTriangle, RotateCcw } from "lucide-react";
import { clearShieldlineLocalState } from "../platform/offlineStore";

interface AppErrorBoundaryState {
  failed: boolean;
}

export class AppErrorBoundary extends Component<{ children: ReactNode }, AppErrorBoundaryState> {
  state: AppErrorBoundaryState = { failed: false };

  static getDerivedStateFromError(): AppErrorBoundaryState {
    return { failed: true };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error("Shieldline UI failed", error, info.componentStack);
  }

  private reset = async () => {
    await clearShieldlineLocalState();
    window.location.reload();
  };

  render() {
    if (!this.state.failed) return this.props.children;
    return (
      <main className="app-recovery" role="alert">
        <AlertTriangle size={32} />
        <h1>Shieldline не вдалося відкрити</h1>
        <p>Локальний стан цієї симуляції несумісний з оновленням. Інші дані браузера не буде змінено.</p>
        <button type="button" onClick={() => { void this.reset(); }}><RotateCcw size={17} /> Відновити Shieldline</button>
      </main>
    );
  }
}
