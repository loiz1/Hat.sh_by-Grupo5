
import React, { useState, useEffect, useCallback } from 'react';
import { EncryptionPanel } from './components/EncryptionPanel';
import { DecryptionPanel } from './components/DecryptionPanel';
import { SettingsIcon, BtcIcon, EthIcon, XmrIcon, CopyIcon, CloseIcon } from './components/icons';
import type { PanelType, Language } from './types';
import { useTranslation } from './contexts/LanguageContext';


// Definir componentes dentro de App.tsx para reducir el número de archivos
const Header: React.FC<{ onSettingsClick: () => void }> = ({ onSettingsClick }) => {
    const { t } = useTranslation();
    return (
        <nav className="bg-white dark:bg-gray-800 shadow-md sticky top-0 z-40">
            <div className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8">
                <div className="flex items-center justify-between h-16">
                    <div className="flex items-center">
                        <span className="text-2xl mr-2">🛡️</span>
                        <h1 className="text-xl font-semibold text-gray-800 dark:text-white">{t('secureFileEncryptor')}</h1>
                    </div>
                    <button onClick={onSettingsClick} className="p-2 rounded-full text-gray-500 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-offset-gray-100 dark:focus:ring-offset-gray-800 focus:ring-primary-500">
                        <SettingsIcon />
                    </button>
                </div>
            </div>
        </nav>
    );
}

const Hero: React.FC = () => {
    const { t } = useTranslation();
    return (
        <section className="bg-gray-100 dark:bg-gray-800">
            <div className="max-w-5xl mx-auto py-12 px-4 sm:px-6 lg:px-8 text-center">
                <h2 className="text-4xl font-extrabold text-gray-900 dark:text-white sm:text-5xl md:text-6xl">
                    {t('clientSideFileEncryption')}
                </h2>
                <p className="mt-4 text-xl text-gray-600 dark:text-gray-300">
                    {t('heroSubtitle')}
                </p>
            </div>
        </section>
    );
}


const Footer: React.FC<{ onDonationsClick: () => void }> = ({ onDonationsClick }) => {
    const { t } = useTranslation();
    return (
        <footer className="bg-white dark:bg-gray-800 border-t border-gray-200 dark:border-gray-700">
            <div className="max-w-5xl mx-auto py-6 px-4 sm:px-6 lg:px-8 text-center text-sm text-gray-500 dark:text-gray-400">
                <p>&copy; {new Date().getFullYear()} {t('copyright')}</p>
                <p className="mt-2">{t('redesignedBy')}</p>
                <button onClick={onDonationsClick} className="mt-2 text-primary-600 dark:text-primary-400 hover:underline">
                    {t('donationsAppreciated')}
                </button>
            </div>
        </footer>
    );
}

const SettingsModal: React.FC<{ isOpen: boolean; onClose: () => void; isDarkMode: boolean; onToggleDarkMode: () => void; }> = ({ isOpen, onClose, isDarkMode, onToggleDarkMode }) => {
    const { t, language, setLanguage } = useTranslation();
    if (!isOpen) return null;

    return (
        <div className="fixed inset-0 bg-black bg-opacity-50 z-50 flex items-center justify-center" onClick={onClose}>
            <div className="bg-white dark:bg-gray-800 rounded-lg shadow-xl p-6 w-full max-w-md" onClick={e => e.stopPropagation()}>
                <div className="flex justify-between items-center mb-4">
                    <h3 className="text-xl font-semibold text-gray-900 dark:text-white">{t('settings')}</h3>
                    <button onClick={onClose} className="p-2 rounded-full text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-700">
                       <CloseIcon />
                    </button>
                </div>
                <div className="space-y-4">
                    <div className="flex items-center justify-between p-3 bg-gray-50 dark:bg-gray-700 rounded-lg">
                        <label htmlFor="language-select" className="font-medium text-gray-700 dark:text-gray-200">{t('language')}</label>
                        <select
                            id="language-select"
                            value={language}
                            onChange={(e) => setLanguage(e.target.value as Language)}
                            className="bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded-md py-1 px-2 text-sm focus:ring-primary-500 focus:border-primary-500"
                        >
                            <option value="en">English</option>
                            <option value="es">Español</option>
                        </select>
                    </div>
                    <div className="flex items-center justify-between p-3 bg-gray-50 dark:bg-gray-700 rounded-lg">
                        <label htmlFor="dark-mode-toggle" className="font-medium text-gray-700 dark:text-gray-200">{t('darkMode')}</label>
                        <button
                            id="dark-mode-toggle"
                            onClick={onToggleDarkMode}
                            className={`relative inline-flex items-center h-6 rounded-full w-11 transition-colors ${isDarkMode ? 'bg-primary-600' : 'bg-gray-200'}`}
                        >
                            <span className={`inline-block w-4 h-4 transform bg-white rounded-full transition-transform ${isDarkMode ? 'translate-x-6' : 'translate-x-1'}`} />
                        </button>
                    </div>
                </div>
            </div>
        </div>
    );
};

const donationsData = [
    { id: 'btc', name: 'Bitcoin', icon: <BtcIcon />, address: 'bc1qlfnq8nu2k84h3jth7a27khaq0p2l2gvtyl2dv6' },
    { id: 'eth', name: 'Ethereum', icon: <EthIcon />, address: '0xF6F204B044CC73Fa90d7A7e4C5EC2947b83b917e' },
    { id: 'xmr', name: 'Monero', icon: <XmrIcon />, address: '84zQq4Xt7sq8cmGryuvWsXFMDvBvHjWjnMQXZWQQRXjB1TgoZWS9zBdNcYL7CRbQBqcDdxr4RtcvCgApmQcU6SemVXd7RuG' },
];

const DonationsModal: React.FC<{ isOpen: boolean; onClose: () => void; showToast: (message: string) => void }> = ({ isOpen, onClose, showToast }) => {
    const { t } = useTranslation();
    const [activeCrypto, setActiveCrypto] = useState('btc');

    const handleCopy = (address: string) => {
        navigator.clipboard.writeText(address);
        showToast(t('addressCopied'));
    };

    if (!isOpen) return null;

    return (
        <div className="fixed inset-0 bg-black bg-opacity-50 z-50 flex items-center justify-center" onClick={onClose}>
            <div className="bg-white dark:bg-gray-800 rounded-lg shadow-xl p-6 w-full max-w-lg" onClick={e => e.stopPropagation()}>
                <div className="flex justify-between items-center mb-4">
                    <h3 className="text-xl font-semibold text-gray-900 dark:text-white">💝 {t('donations')}</h3>
                    <button onClick={onClose} className="p-2 rounded-full text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-700">
                        <CloseIcon />
                    </button>
                </div>
                <div className="bg-gradient-to-r from-blue-50 to-purple-50 dark:from-gray-700 dark:to-gray-600 p-4 rounded-lg mb-4">
                    <p className="text-gray-800 dark:text-gray-200 font-medium text-center">
                        Cambio realizado por solicitud del Profe
                    </p>
                </div>
                <div className="border-b border-gray-200 dark:border-gray-700">
                    <nav className="-mb-px flex space-x-4" aria-label="Tabs">
                        {donationsData.map(crypto => (
                            <button
                                key={crypto.id}
                                onClick={() => setActiveCrypto(crypto.id)}
                                className={`whitespace-nowrap flex items-center py-3 px-1 border-b-2 font-medium text-sm ${activeCrypto === crypto.id ? 'border-primary-500 text-primary-600 dark:text-primary-400' : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300 dark:text-gray-400 dark:hover:text-gray-200 dark:hover:border-gray-500'}`}
                            >
                                {crypto.icon}
                                <span className="ml-2">{crypto.name}</span>
                            </button>
                        ))}
                    </nav>
                </div>
                <div className="mt-4">
                    {donationsData.map(crypto => (
                        <div key={crypto.id} className={`${activeCrypto === crypto.id ? 'block' : 'hidden'}`}>
                            <label className="text-sm font-medium text-gray-700 dark:text-gray-300">{crypto.name} Address:</label>
                            <div className="mt-1 relative rounded-md shadow-sm">
                                <input
                                    type="text"
                                    readOnly
                                    value={crypto.address}
                                    className="w-full p-3 pr-10 bg-gray-50 dark:bg-gray-900 border border-gray-300 dark:border-gray-600 rounded-md text-gray-700 dark:text-gray-200 font-mono text-sm"
                                />
                                <button onClick={() => handleCopy(crypto.address)} className="absolute inset-y-0 right-0 pr-3 flex items-center text-gray-500 hover:text-primary-500">
                                    <CopyIcon />
                                </button>
                            </div>
                        </div>
                    ))}
                </div>
            </div>
        </div>
    );
};


const Toast: React.FC<{ message: string, isVisible: boolean }> = ({ message, isVisible }) => (
    <div className={`fixed bottom-5 right-5 bg-gray-900 dark:bg-gray-100 text-white dark:text-black py-2 px-4 rounded-lg shadow-lg transition-opacity duration-300 ${isVisible ? 'opacity-100' : 'opacity-0'}`}>
        {message}
    </div>
);


export default function App() {
    const { t } = useTranslation();
    const [panel, setPanel] = useState<PanelType>('encryption');
    const [isSettingsOpen, setSettingsOpen] = useState(false);
    const [isDonationsOpen, setDonationsOpen] = useState(false);
    const [isDarkMode, setDarkMode] = useState(false);
    
    const [toast, setToast] = useState({ message: '', isVisible: false });

    const showToast = useCallback((message: string) => {
        setToast({ message, isVisible: true });
        setTimeout(() => {
            setToast(t => ({...t, isVisible: false}));
        }, 3000);
    }, []);

    useEffect(() => {
        const darkModePreference = localStorage.getItem('darkMode') === 'true';
        setDarkMode(darkModePreference);
        if (darkModePreference) {
            document.documentElement.classList.add('dark');
        }
    }, []);

    const toggleDarkMode = () => {
        setDarkMode(prev => {
            const newMode = !prev;
            localStorage.setItem('darkMode', String(newMode));
            if (newMode) {
                document.documentElement.classList.add('dark');
            } else {
                document.documentElement.classList.remove('dark');
            }
            return newMode;
        });
    };

    return (
        <div className="min-h-screen flex flex-col font-sans text-gray-800 dark:text-gray-200">
            <Header onSettingsClick={() => setSettingsOpen(true)} />
            <Hero />
            <main className="flex-grow w-full max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
                <div className="bg-white dark:bg-gray-800 rounded-xl shadow-lg p-4 sm:p-8">
                    <div className="mb-6 border-b border-gray-200 dark:border-gray-700">
                        <nav className="-mb-px flex space-x-6" aria-label="Tabs">
                            <button
                                onClick={() => setPanel('encryption')}
                                className={`whitespace-nowrap py-4 px-1 border-b-2 font-medium text-lg ${panel === 'encryption' ? 'border-primary-500 text-primary-600 dark:text-primary-400' : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300 dark:text-gray-400 dark:hover:text-gray-200 dark:hover:border-gray-500'}`}
                            >
                                {t('encrypt')}
                            </button>
                            <button
                                onClick={() => setPanel('decryption')}
                                className={`whitespace-nowrap py-4 px-1 border-b-2 font-medium text-lg ${panel === 'decryption' ? 'border-primary-500 text-primary-600 dark:text-primary-400' : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300 dark:text-gray-400 dark:hover:text-gray-200 dark:hover:border-gray-500'}`}
                            >
                                {t('decrypt')}
                            </button>
                        </nav>
                    </div>

                    <div>
                        {panel === 'encryption' && <EncryptionPanel showToast={showToast} />}
                        {panel === 'decryption' && <DecryptionPanel showToast={showToast} />}
                    </div>
                </div>
            </main>
            <Footer onDonationsClick={() => setDonationsOpen(true)} />
            <SettingsModal isOpen={isSettingsOpen} onClose={() => setSettingsOpen(false)} isDarkMode={isDarkMode} onToggleDarkMode={toggleDarkMode} />
            <DonationsModal isOpen={isDonationsOpen} onClose={() => setDonationsOpen(false)} showToast={showToast} />
            <Toast message={toast.message} isVisible={toast.isVisible} />
        </div>
    );
}
