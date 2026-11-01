import React, { useState, useEffect, useRef } from 'react';
import { useAuth } from '../../context/AuthContext.js';
import { Building2, ShieldCheck, Clock, ChevronDown, Check, Lock } from 'lucide-react';

export const Navbar: React.FC = () => {
  const { user, selectedSite, setSelectedSite, sites } = useAuth();
  const [currentTime, setCurrentTime] = useState<string>('');
  const [isOpen, setIsOpen] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const updateTime = () => {
      const now = new Date();
      setCurrentTime(
        now.toLocaleDateString(undefined, {
          weekday: 'short',
          month: 'short',
          day: 'numeric',
          hour: '2-digit',
          minute: '2-digit',
          second: '2-digit',
        })
      );
    };
    updateTime();
    const interval = setInterval(updateTime, 1000);
    return () => clearInterval(interval);
  }, []);

  // Close dropdown on outside click or Escape key
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setIsOpen(false);
      }
    };
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        setIsOpen(false);
      }
    };

    if (isOpen) {
      document.addEventListener('mousedown', handleClickOutside);
      document.addEventListener('keydown', handleKeyDown);
    }
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
      document.removeEventListener('keydown', handleKeyDown);
    };
  }, [isOpen]);

  const activeSite = sites.find((s) => s.siteCode === selectedSite) || {
    siteCode: selectedSite || 'PLANT-001',
    name: 'Demo Industrial Effluent Treatment Facility',
  };

  return (
    <header className="top-command-bar">
      <div className="command-bar-left">
        {/* Modern SaaS Custom Workspace / Facility Switcher Dropdown */}
        {user && (
          <div className="site-switcher-container" ref={dropdownRef}>
            <button
              type="button"
              className={`site-switcher-trigger ${isOpen ? 'active' : ''}`}
              onClick={() => setIsOpen(!isOpen)}
              aria-haspopup="listbox"
              aria-expanded={isOpen}
              title="Click to switch active monitoring facility"
            >
              <div className="site-switcher-icon">
                <Building2 size={16} />
              </div>
              <div className="site-switcher-text">
                <span className="site-switcher-eyebrow">Active Monitored Facility</span>
                <span className="site-switcher-label">
                  <strong>{activeSite.siteCode}</strong> — {activeSite.name}
                </span>
              </div>
              <ChevronDown
                size={15}
                className={`site-switcher-arrow ${isOpen ? 'rotated' : ''}`}
              />
            </button>

            {/* Custom Floating Dropdown Menu Card */}
            {isOpen && (
              <div className="site-dropdown-menu" role="listbox">
                <div className="site-dropdown-header">
                  <span>Select Monitored Facility</span>
                  <span className="site-dropdown-count">{sites.length} accessible</span>
                </div>

                <div className="site-dropdown-list">
                  {sites.map((site) => {
                    const isSelected = site.siteCode === selectedSite;
                    return (
                      <button
                        key={site.siteCode}
                        type="button"
                        role="option"
                        aria-selected={isSelected}
                        className={`site-dropdown-item ${isSelected ? 'selected' : ''}`}
                        onClick={() => {
                          setSelectedSite(site.siteCode);
                          setIsOpen(false);
                        }}
                      >
                        <div className="site-item-left">
                          <span className={`site-item-dot ${isSelected ? 'active' : ''}`} />
                          <div className="site-item-details">
                            <div className="site-item-code">{site.siteCode}</div>
                            <div className="site-item-name">{site.name}</div>
                          </div>
                        </div>
                        {isSelected && <Check size={16} className="site-item-check" />}
                      </button>
                    );
                  })}
                </div>

                <div className="site-dropdown-footer">
                  <Lock size={12} />
                  <span>Site boundary cryptographically enforced by ES256 session tokens</span>
                </div>
              </div>
            )}
          </div>
        )}

        <div className="facility-status-tag">
          <span className="facility-status-dot" />
          <span>Dual-Delivery Witness Active</span>
        </div>
      </div>

      <div className="command-bar-right">
        {/* Real-time Clock */}
        <div className="clock-pill">
          <Clock size={14} className="clock-icon" />
          <span>{currentTime || 'Synchronizing UTC...'}</span>
        </div>

        {/* Cryptographic Trust Indicator */}
        <div className="trust-indicator-pill">
          <ShieldCheck size={15} className="trust-icon" />
          <span>ES256 / Ed25519 Anchored</span>
        </div>

        {/* Subtle Prototype Watermark Chip */}
        <div className="prototype-watermark-chip" title="Simulated Industrial Data for Demonstration">
          SIMULATED DATA
        </div>
      </div>
    </header>
  );
};
