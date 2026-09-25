import { memo, useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Background, Handle, Position, ReactFlow, type Edge, type Node, type NodeMouseHandler, type NodeProps } from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import './mission-flow.css';

export type MissionFlowStatus = 'pending' | 'active' | 'complete' | 'held';

export interface MissionFlowStep {
  id: string;
  label: string;
  status: MissionFlowStatus;
  detail?: string;
  targetId?: string;
}

export interface MissionFlowProps {
  steps: MissionFlowStep[];
  onStepSelect?: (id: string) => void;
}

const NODE_WIDTH = 232;
const NODE_HEIGHT = 120;
const COLUMN_GAP = 24;
const ROW_GAP = 28;
const HORIZONTAL_INSET = 16;
const VERTICAL_INSET = 20;

const statusLabels: Record<MissionFlowStatus, string> = {
  pending: 'Pending',
  active: 'Active',
  complete: 'Complete',
  held: 'Held',
};

function getColumnCount(width: number): number {
  if (width >= 1288) return 5;
  if (width >= 776) return 3;
  if (width >= 520) return 2;
  return 1;
}

type MissionStageNodeData = { step: MissionFlowStep; index: number };
type MissionStageNodeType = Node<MissionStageNodeData, 'missionStage'>;

function StageContent({ step, index }: { step: MissionFlowStep; index: number }) {
  return (
    <div className="mission-flow__stage" data-status={step.status}>
      <div className="mission-flow__stage-topline">
        <span className="mission-flow__stage-index">STAGE {String(index).padStart(2, '0')}</span>
        <span className={`mission-flow__status mission-flow__status--${step.status}`}>
          <span className="mission-flow__status-mark" aria-hidden="true" />
          {statusLabels[step.status]}
        </span>
      </div>
      <span className="mission-flow__stage-label">{step.label}</span>
      {step.detail ? <span className="mission-flow__stage-detail">{step.detail}</span> : null}
    </div>
  );
}

function MissionStageNode({ data }: NodeProps<MissionStageNodeType>) {
  return (
    <>
      <Handle id="top-target" type="target" position={Position.Top} />
      <Handle id="top-source" type="source" position={Position.Top} />
      <Handle id="right-target" type="target" position={Position.Right} />
      <Handle id="right-source" type="source" position={Position.Right} />
      <Handle id="bottom-target" type="target" position={Position.Bottom} />
      <Handle id="bottom-source" type="source" position={Position.Bottom} />
      <Handle id="left-target" type="target" position={Position.Left} />
      <Handle id="left-source" type="source" position={Position.Left} />
      <StageContent step={data.step} index={data.index} />
    </>
  );
}

const nodeTypes = { missionStage: MissionStageNode };

function MissionFlowView({ steps, onStepSelect }: MissionFlowProps) {
  const [width, setWidth] = useState(0);
  const frameRef = useRef<HTMLDivElement>(null);
  const columns = getColumnCount(width);
  const rowCount = Math.max(1, Math.ceil(steps.length / columns));

  useEffect(() => {
    const element = frameRef.current;
    if (!element) return;
    const observer = new ResizeObserver(([entry]) => setWidth(entry.contentRect.width));
    observer.observe(element);
    setWidth(element.getBoundingClientRect().width);
    return () => observer.disconnect();
  }, []);

  const { nodes, edges } = useMemo(() => {
    const nodePositions = new Map(steps.map((step, index) => [
      step.id,
      { row: Math.floor(index / columns), column: index % columns },
    ] as const));
    const nextNodes: Node[] = steps.map((step, nodeIndex) => {
      const row = Math.floor(nodeIndex / columns);
      const column = nodeIndex % columns;
      return {
        id: step.id,
        type: 'missionStage',
        position: {
          x: HORIZONTAL_INSET + column * (NODE_WIDTH + COLUMN_GAP),
          y: VERTICAL_INSET + row * (NODE_HEIGHT + ROW_GAP),
        },
        data: { step, index: nodeIndex + 1 },
        className: 'mission-flow__node',
        style: { width: NODE_WIDTH, height: NODE_HEIGHT },
        draggable: false,
        selectable: false,
        connectable: false,
        focusable: false,
        ariaLabel: `${step.label}, ${statusLabels[step.status]}${step.detail ? `, ${step.detail}` : ''}`,
      };
    });

    const nextEdges: Edge[] = steps.flatMap((step) => (
      step.targetId && nodePositions.has(step.targetId)
        ? [{
            id: `${step.id}-${step.targetId}`,
            source: step.id,
            target: step.targetId,
            sourceHandle: getHandleId(nodePositions.get(step.id)!, nodePositions.get(step.targetId)!, 'source'),
            targetHandle: getHandleId(nodePositions.get(step.targetId)!, nodePositions.get(step.id)!, 'target'),
            type: 'smoothstep',
            className: `mission-flow__edge mission-flow__edge--${step.status}`,
            selectable: false,
            focusable: false,
          }]
        : []
    ));

    return { nodes: nextNodes, edges: nextEdges };
  }, [columns, steps]);

  const handleNodeClick: NodeMouseHandler = useCallback((_event, node) => {
    onStepSelect?.(node.id);
  }, [onStepSelect]);

  const graphWidth = HORIZONTAL_INSET * 2 + columns * NODE_WIDTH + (columns - 1) * COLUMN_GAP;
  const graphHeight = VERTICAL_INSET * 2 + rowCount * NODE_HEIGHT + (rowCount - 1) * ROW_GAP;

  return (
    <section className="mission-flow" aria-label="Mission stages">
      <div className="mission-flow__heading">
        <div>
          <p className="mission-flow__eyebrow">MISSION OVERVIEW</p>
          <h2 className="mission-flow__title">Stages</h2>
        </div>
        <span className="mission-flow__stage-count">{steps.length} {steps.length === 1 ? 'stage' : 'stages'}</span>
      </div>

      <div className="mission-flow__graph-frame" ref={frameRef}>
        <div className="mission-flow__graph" style={{ height: graphHeight, width: graphWidth }}>
          <ReactFlow
            nodes={nodes}
            edges={edges}
            nodeTypes={nodeTypes}
            onNodeClick={onStepSelect ? handleNodeClick : undefined}
            nodesDraggable={false}
            nodesConnectable={false}
            elementsSelectable={false}
            panOnDrag={false}
            panOnScroll={false}
            zoomOnScroll={false}
            zoomOnPinch={false}
            zoomOnDoubleClick={false}
            preventScrolling={false}
          >
            <Background color="rgba(186, 203, 188, 0.13)" gap={20} size={1} />
          </ReactFlow>
        </div>
      </div>

      <details className="mission-flow__directory">
        <summary className="mission-flow__directory-summary">Open ordered stage list <span>{steps.length} stages</span></summary>
        <ol className="mission-flow__list" aria-label="Mission stages in supplied order">
          {steps.map((step, index) => (
            <li className="mission-flow__list-item" key={step.id}>
              {onStepSelect ? (
                <button className="mission-flow__list-button" type="button" onClick={() => onStepSelect(step.id)}>
                  <StageContent step={step} index={index + 1} />
                </button>
              ) : (
                <div className="mission-flow__list-static"><StageContent step={step} index={index + 1} /></div>
              )}
            </li>
          ))}
        </ol>
      </details>

      <ol className="mission-flow__mobile-list" aria-label="Mission stages in supplied order">
        {steps.map((step, index) => (
          <li className="mission-flow__mobile-item" key={step.id}>
            {onStepSelect ? (
              <button className="mission-flow__mobile-button" type="button" onClick={() => onStepSelect(step.id)}>
                <span className="mission-flow__mobile-index">{String(index + 1).padStart(2, '0')}</span>
                <span className="mission-flow__mobile-label">{step.label}</span>
                <span className={`mission-flow__status mission-flow__status--${step.status}`}>
                  <span className="mission-flow__status-mark" aria-hidden="true" />
                  {statusLabels[step.status]}
                </span>
              </button>
            ) : (
              <div className="mission-flow__mobile-static">
                <span className="mission-flow__mobile-index">{String(index + 1).padStart(2, '0')}</span>
                <span className="mission-flow__mobile-label">{step.label}</span>
                <span className={`mission-flow__status mission-flow__status--${step.status}`}>
                  <span className="mission-flow__status-mark" aria-hidden="true" />
                  {statusLabels[step.status]}
                </span>
              </div>
            )}
            {step.detail ? <p className="mission-flow__mobile-detail">{step.detail}</p> : null}
          </li>
        ))}
      </ol>
    </section>
  );
}

function getHandleId(position: { row: number; column: number }, other: { row: number; column: number }, role: 'source' | 'target') {
  const side = position.row === other.row
    ? (position.column < other.column ? 'right' : 'left')
    : (position.row < other.row ? 'bottom' : 'top');
  return `${side}-${role}`;
}

export const MissionFlow = memo(MissionFlowView);
