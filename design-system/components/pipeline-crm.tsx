/**
 * THE PIPELINE - CRM Revolutionized
 * Deal flow visualization that feels like the future
 */

import React, { useState, useRef, useCallback } from 'react';
import { motion, AnimatePresence, useDragControls, useMotionValue, useTransform, PanInfo } from 'framer-motion';
import { DollarSign, Calendar, Building, User, AlertCircle, Zap, TrendingUp, Clock, ChevronRight, Plus } from 'lucide-react';

// ============================================
// DEAL CARD - Minimal yet complete
// ============================================

export interface Deal {
  id: string;
  company: string;
  amount: number;
  stage: string;
  daysInStage: number;
  probability: number;
  owner?: string;
  nextAction?: string;
  lastActivity?: Date;
  priority?: 'high' | 'medium' | 'low';
  tags?: string[];
  contacts?: number;
  aiSuggestion?: string;
}

interface DealCardProps {
  deal: Deal;
  onMove?: (dealId: string, newStage: string) => void;
  onClick?: (deal: Deal) => void;
  isDragging?: boolean;
}

const DealCard: React.FC<DealCardProps> = ({ deal, onMove, onClick, isDragging }) => {
  const controls = useDragControls();
  const [isHovered, setIsHovered] = useState(false);

  const formatAmount = (amount: number) => {
    if (amount >= 1000000) {
      return `$${(amount / 1000000).toFixed(1)}M`;
    }
    if (amount >= 1000) {
      return `$${(amount / 1000).toFixed(0)}K`;
    }
    return `$${amount}`;
  };

  const getPriorityColor = (priority?: string) => {
    switch (priority) {
      case 'high': return 'text-red-500';
      case 'medium': return 'text-amber-500';
      default: return 'text-black/36 dark:text-white/36';
    }
  };

  return (
    <motion.div
      drag
      dragControls={controls}
      dragListener={false}
      dragElastic={0.2}
      dragTransition={{ bounceStiffness: 300, bounceDamping: 20 }}
      whileHover={{ scale: 1.02, y: -2 }}
      whileDrag={{ scale: 1.05, rotate: 2 }}
      onMouseEnter={() => setIsHovered(true)}
      onMouseLeave={() => setIsHovered(false)}
      onClick={() => onClick?.(deal)}
      className={`
        relative p-4 bg-white dark:bg-black
        border border-black/8 dark:border-white/8
        cursor-pointer select-none
        ${isDragging ? 'opacity-50' : ''}
      `}
      style={{ touchAction: 'none' }}
      onPointerDown={(e) => controls.start(e)}
    >
      {/* Main Content */}
      <div className="space-y-2">
        <div className="flex items-start justify-between">
          <h3 className="font-medium text-black dark:text-white leading-tight">
            {deal.company}
          </h3>
          {deal.priority === 'high' && (
            <Zap className={`w-3 h-3 ${getPriorityColor(deal.priority)}`} />
          )}
        </div>

        <div className="flex items-center justify-between">
          <span className="text-[20px] font-medium text-black dark:text-white">
            {formatAmount(deal.amount)}
          </span>
          <span className="text-[13px] text-black/36 dark:text-white/36">
            {deal.probability}%
          </span>
        </div>

        <div className="flex items-center gap-3 text-[11px] text-black/36 dark:text-white/36">
          <div className="flex items-center gap-1">
            <Clock className="w-3 h-3" />
            {deal.daysInStage}d
          </div>
          {deal.contacts && (
            <div className="flex items-center gap-1">
              <User className="w-3 h-3" />
              {deal.contacts}
            </div>
          )}
        </div>
      </div>

      {/* AI Suggestion on Hover */}
      <AnimatePresence>
        {isHovered && deal.aiSuggestion && (
          <motion.div
            initial={{ opacity: 0, y: 4 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: 4 }}
            className="absolute top-full left-0 right-0 mt-1 p-2 bg-blue-500/10 text-[11px] text-blue-700 dark:text-blue-400 z-10"
          >
            💡 {deal.aiSuggestion}
          </motion.div>
        )}
      </AnimatePresence>

      {/* Stage Indicator Line */}
      <motion.div
        className="absolute bottom-0 left-0 right-0 h-0.5 bg-gradient-to-r from-blue-500 to-blue-400"
        initial={{ scaleX: 0 }}
        animate={{ scaleX: deal.probability / 100 }}
        transition={{ duration: 0.5, ease: [0.4, 0, 0.2, 1] }}
      />
    </motion.div>
  );
};

// ============================================
// PIPELINE STAGE - Container with physics
// ============================================

interface PipelineStageProps {
  title: string;
  deals: Deal[];
  totalValue: number;
  onDrop?: (dealId: string, stageId: string) => void;
  onAddDeal?: () => void;
  isHighlighted?: boolean;
}

const PipelineStage: React.FC<PipelineStageProps> = ({
  title,
  deals,
  totalValue,
  onDrop,
  onAddDeal,
  isHighlighted
}) => {
  const [isDragOver, setIsDragOver] = useState(false);

  const formatTotalValue = (value: number) => {
    if (value >= 1000000) {
      return `$${(value / 1000000).toFixed(1)}M`;
    }
    if (value >= 1000) {
      return `$${Math.round(value / 1000)}K`;
    }
    return `$${value}`;
  };

  return (
    <motion.div
      className={`
        flex-1 min-w-[280px] flex flex-col
        ${isHighlighted ? 'ring-2 ring-blue-500' : ''}
      `}
      animate={{ backgroundColor: isDragOver ? 'rgba(0, 102, 255, 0.02)' : 'transparent' }}
      onDragOver={(e) => {
        e.preventDefault();
        setIsDragOver(true);
      }}
      onDragLeave={() => setIsDragOver(false)}
      onDrop={(e) => {
        e.preventDefault();
        setIsDragOver(false);
        // Handle drop logic
      }}
    >
      {/* Stage Header */}
      <div className="mb-4">
        <div className="flex items-center justify-between mb-2">
          <h2 className="text-[13px] font-medium text-black/64 dark:text-white/64 uppercase tracking-wide">
            {title}
          </h2>
          <button
            onClick={onAddDeal}
            className="w-6 h-6 flex items-center justify-center rounded hover:bg-black/8 dark:hover:bg-white/8 transition-colors"
          >
            <Plus className="w-3 h-3 text-black/36 dark:text-white/36" />
          </button>
        </div>
        <div className="flex items-baseline gap-2">
          <span className="text-[20px] font-medium text-black dark:text-white">
            {formatTotalValue(totalValue)}
          </span>
          <span className="text-[13px] text-black/36 dark:text-white/36">
            {deals.length} {deals.length === 1 ? 'deal' : 'deals'}
          </span>
        </div>
      </div>

      {/* Deals List */}
      <div className="flex-1 space-y-3 overflow-y-auto min-h-[200px]">
        <AnimatePresence>
          {deals.map((deal, index) => (
            <motion.div
              key={deal.id}
              initial={{ opacity: 0, x: -20 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: 20 }}
              transition={{ delay: index * 0.05 }}
            >
              <DealCard deal={deal} />
            </motion.div>
          ))}
        </AnimatePresence>

        {/* Empty State */}
        {deals.length === 0 && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            className="h-32 flex items-center justify-center text-[13px] text-black/24 dark:text-white/24"
          >
            Drop deals here
          </motion.div>
        )}
      </div>
    </motion.div>
  );
};

// ============================================
// THE PIPELINE - Main Component
// ============================================

interface PipelineProps {
  stages: {
    id: string;
    title: string;
    deals: Deal[];
  }[];
  onDealMove?: (dealId: string, fromStage: string, toStage: string) => void;
  onDealClick?: (deal: Deal) => void;
  onAddDeal?: (stageId: string) => void;
  viewMode?: 'pipeline' | 'forecast' | 'velocity';
}

export const Pipeline: React.FC<PipelineProps> = ({
  stages,
  onDealMove,
  onDealClick,
  onAddDeal,
  viewMode = 'pipeline'
}) => {
  const [selectedStage, setSelectedStage] = useState<string | null>(null);
  const scrollRef = useRef<HTMLDivElement>(null);

  // Calculate totals
  const stageTotals = stages.map(stage => ({
    ...stage,
    totalValue: stage.deals.reduce((sum, deal) => sum + deal.amount, 0),
    avgProbability: stage.deals.length > 0
      ? stage.deals.reduce((sum, deal) => sum + deal.probability, 0) / stage.deals.length
      : 0
  }));

  const totalPipelineValue = stageTotals.reduce((sum, stage) => sum + stage.totalValue, 0);

  return (
    <div className="flex flex-col h-full">
      {/* Pipeline Header */}
      <div className="mb-6">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h1 className="text-[28px] font-medium text-black dark:text-white">
              Pipeline
            </h1>
            <div className="text-[13px] text-black/64 dark:text-white/64">
              Total Value: {totalPipelineValue >= 1000000 ? `$${(totalPipelineValue / 1000000).toFixed(1)}M` : `$${Math.round(totalPipelineValue / 1000)}K`}
            </div>
          </div>

          {/* View Mode Selector */}
          <div className="flex gap-1">
            {(['pipeline', 'forecast', 'velocity'] as const).map(mode => (
              <button
                key={mode}
                onClick={() => {/* Handle view mode change */}}
                className={`
                  px-4 py-2 text-[13px] capitalize transition-all duration-200
                  ${viewMode === mode
                    ? 'text-black dark:text-white bg-black/8 dark:bg-white/8'
                    : 'text-black/36 dark:text-white/36 hover:text-black dark:hover:text-white'
                  }
                `}
              >
                {mode}
              </button>
            ))}
          </div>
        </div>

        {/* Stage Progress Visualization */}
        <div className="relative h-1 bg-black/8 dark:bg-white/8 overflow-hidden">
          {stageTotals.map((stage, index) => (
            <motion.div
              key={stage.id}
              className="absolute top-0 h-full bg-gradient-to-r from-blue-500 to-blue-400"
              initial={{ left: `${(index / stages.length) * 100}%`, width: 0 }}
              animate={{
                left: `${(index / stages.length) * 100}%`,
                width: `${(stage.totalValue / totalPipelineValue) * 100}%`
              }}
              transition={{ duration: 0.5, ease: [0.4, 0, 0.2, 1] }}
            />
          ))}
        </div>
      </div>

      {/* Pipeline Stages */}
      <div
        ref={scrollRef}
        className="flex-1 flex gap-px bg-black/8 dark:bg-white/8 overflow-x-auto"
      >
        {stageTotals.map((stage, index) => (
          <div
            key={stage.id}
            className="bg-white dark:bg-black p-5 flex-1 min-w-[280px]"
          >
            <PipelineStage
              title={stage.title}
              deals={stage.deals}
              totalValue={stage.totalValue}
              onDrop={(dealId) => onDealMove?.(dealId, '', stage.id)}
              onAddDeal={() => onAddDeal?.(stage.id)}
              isHighlighted={selectedStage === stage.id}
            />
          </div>
        ))}
      </div>

      {/* AI Insights Bar */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="mt-6 p-4 bg-gradient-to-r from-blue-500/5 to-transparent border-l-2 border-blue-500"
      >
        <div className="flex items-center gap-3">
          <Zap className="w-4 h-4 text-blue-500" />
          <div className="flex-1">
            <div className="text-[13px] font-medium text-black dark:text-white">
              AI Pipeline Analysis
            </div>
            <div className="text-[11px] text-black/64 dark:text-white/64 mt-1">
              3 deals likely to close this week • 2 deals need attention • $1.2M forecast confidence: 78%
            </div>
          </div>
          <ChevronRight className="w-4 h-4 text-black/36 dark:text-white/36" />
        </div>
      </motion.div>
    </div>
  );
};

export default Pipeline;