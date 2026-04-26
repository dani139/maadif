import { useState } from 'react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import {
  Layout,
  Dashboard,
  VersionTracker,
  ApkLibrary,
  AnalysisJobs,
  Settings,
} from './components';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      refetchOnWindowFocus: false,
      retry: 1,
      staleTime: 30000,
    },
  },
});

type View = 'dashboard' | 'versions' | 'apks' | 'analysis' | 'settings';

function App() {
  const [currentView, setCurrentView] = useState<View>('dashboard');

  const renderView = () => {
    switch (currentView) {
      case 'dashboard':
        return <Dashboard />;
      case 'versions':
        return <VersionTracker onNavigateToLibrary={() => setCurrentView('apks')} />;
      case 'apks':
        return <ApkLibrary />;
      case 'analysis':
        return <AnalysisJobs />;
      case 'settings':
        return <Settings />;
      default:
        return <Dashboard />;
    }
  };

  return (
    <QueryClientProvider client={queryClient}>
      <Layout currentView={currentView} onViewChange={setCurrentView}>
        {renderView()}
      </Layout>
    </QueryClientProvider>
  );
}

export default App;
