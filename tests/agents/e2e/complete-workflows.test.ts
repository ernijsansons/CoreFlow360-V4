/**
 * End-to-End Agent Workflow Tests
 * Tests complete business workflows from start to finish
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import {
  SimpleTestEnvironmentFactory,
  SimpleTaskGenerator,
  SimplePerformanceMonitor,
  type MockTestEnvironment
} from './test-utils';
import {
  AgentTask,
  BusinessContext,
  AgentResult,
  TaskPriority
} from '../../../src/modules/agents/types';

describe('Complete Agent Workflows E2E', () => {
  let testEnv: MockTestEnvironment;
  let businessContext: BusinessContext;
  let performanceMonitor: SimplePerformanceMonitor;

  beforeEach(async () => {
    testEnv = await SimpleTestEnvironmentFactory.create();
    businessContext = testEnv.businessContext;
    performanceMonitor = new SimplePerformanceMonitor();
  });

  afterEach(async () => {
    await SimpleTestEnvironmentFactory.cleanup(testEnv);
  });

  describe('Sales and CRM Workflows', () => {
    it('should execute complete lead-to-customer conversion workflow', async () => {
      const workflowId = 'lead-conversion-e2e-001';
      performanceMonitor.start();

      // Step 1: Lead Capture and Initial Processing
      const leadCaptureTask = SimpleTaskGenerator.generate({
        capability: 'lead_processing',
        context: businessContext,
        input: {
          prompt: 'Process incoming lead from website form',
          data: {
            lead: {
              firstName: 'Sarah',
              lastName: 'Johnson',
              email: 'sarah.johnson@techcorp.com',
              company: 'TechCorp Solutions',
              phone: '+1-555-0123',
              industry: 'Technology',
              employees: 250,
              source: 'website_form',
              interests: ['enterprise_software', 'automation', 'analytics'],
              budget: 100000,
              timeline: '3-6 months'
            }
          },
          parameters: {
            validateData: true,
            enrichProfile: true,
            scoreQuality: true
          }
        },
        metadata: { workflowId, step: 'lead_capture', stepIndex: 1 }
      });

      const leadResult = await testEnv.orchestrator.executeTask(leadCaptureTask, businessContext);
      expect(leadResult.status).toBe('completed');

      // Step 2: Lead Qualification and Scoring
      const qualificationTask = SimpleTaskGenerator.generate({
        capability: 'lead_qualification',
        context: businessContext,
        input: {
          prompt: 'Qualify and score the processed lead',
          data: {
            leadData: leadResult.result.data,
            qualificationCriteria: {
              budgetMinimum: 50000,
              employeeCountMinimum: 100,
              industryMatch: ['Technology', 'Software', 'Healthcare'],
              timelineMaximum: 12
            }
          },
          parameters: {
            useMLScoring: true,
            includeRecommendations: true
          }
        },
        metadata: { workflowId, step: 'lead_qualification', stepIndex: 2 }
      });

      const qualificationResult = await testEnv.orchestrator.executeTask(qualificationTask, businessContext);
      expect(qualificationResult.status).toBe('completed');

      // Step 3: Sales Assignment and Territory Routing
      const assignmentTask = SimpleTaskGenerator.generate({
        capability: 'sales_assignment',
        context: businessContext,
        input: {
          prompt: 'Assign qualified lead to appropriate sales representative',
          data: {
            qualifiedLead: qualificationResult.result.data,
            assignmentCriteria: {
              territory: 'West Coast',
              industry: 'Technology',
              dealSize: 'enterprise',
              priority: 'high'
            }
          },
          parameters: {
            considerWorkload: true,
            matchExpertise: true
          }
        },
        metadata: { workflowId, step: 'sales_assignment', stepIndex: 3 }
      });

      const assignmentResult = await testEnv.orchestrator.executeTask(assignmentTask, businessContext);
      expect(assignmentResult.status).toBe('completed');

      // Step 4: Opportunity Creation and Tracking
      const opportunityTask = SimpleTaskGenerator.generate({
        capability: 'opportunity_management',
        context: businessContext,
        input: {
          prompt: 'Create sales opportunity and set up tracking',
          data: {
            assignedLead: assignmentResult.result.data,
            opportunityDetails: {
              value: 100000,
              probability: 0.7,
              stage: 'qualification',
              expectedCloseDate: '2024-06-30',
              products: ['enterprise_platform', 'analytics_module']
            }
          },
          parameters: {
            setupFollowUp: true,
            createTasks: true,
            notifyTeam: true
          }
        },
        metadata: { workflowId, step: 'opportunity_creation', stepIndex: 4 }
      });

      const opportunityResult = await testEnv.orchestrator.executeTask(opportunityTask, businessContext);
      expect(opportunityResult.status).toBe('completed');

      // Step 5: Automated Follow-up and Nurturing
      const nurturingTask = SimpleTaskGenerator.generate({
        capability: 'lead_nurturing',
        context: businessContext,
        input: {
          prompt: 'Set up automated nurturing campaign',
          data: {
            opportunity: opportunityResult.result.data,
            nurturingStrategy: {
              duration: '90 days',
              touchpoints: ['email', 'phone', 'content'],
              frequency: 'weekly',
              personalization: 'high'
            }
          },
          parameters: {
            scheduleAutomation: true,
            personalizeContent: true,
            trackEngagement: true
          }
        },
        metadata: { workflowId, step: 'lead_nurturing', stepIndex: 5 }
      });

      const nurturingResult = await testEnv.orchestrator.executeTask(nurturingTask, businessContext);
      expect(nurturingResult.status).toBe('completed');

      performanceMonitor.end();

      // Verify complete workflow
      const allResults = [leadResult, qualificationResult, assignmentResult, opportunityResult, nurturingResult];

      expect(allResults).toHaveLength(5);
      allResults.forEach((result, index) => {
        expect(result.status).toBe('completed');
        expect(result.metadata?.workflowId).toBe(workflowId);
        expect(result.metadata?.stepIndex).toBe(index + 1);
      });

      // Verify workflow continuity
      expect(qualificationResult.metadata?.previousStep).toBeDefined;
      expect(assignmentResult.metadata?.previousStep).toBeDefined;

      // Performance validation
      expect(performanceMonitor.getExecutionTime()).toBeLessThan(30000); // 30 seconds total
    });

    it('should handle customer onboarding workflow', async () => {
      const workflowId = 'customer-onboarding-e2e-001';

      // Step 1: Customer Account Setup
      const accountSetupTask = SimpleTaskGenerator.generate({
        capability: 'account_management',
        context: businessContext,
        input: {
          prompt: 'Set up new customer account',
          data: {
            customer: {
              companyName: 'Innovation Labs Inc.',
              contactPerson: 'David Chen',
              email: 'david.chen@innovationlabs.com',
              plan: 'enterprise',
              contractValue: 120000,
              startDate: '2024-04-01'
            }
          },
          parameters: {
            provisionResources: true,
            setupIntegrations: true,
            createWelcomePackage: true
          }
        },
        metadata: { workflowId, step: 'account_setup' }
      });

      const accountResult = await testEnv.orchestrator.executeTask(accountSetupTask, businessContext);
      expect(accountResult.status).toBe('completed');

      // Step 2: Training and Knowledge Transfer
      const trainingTask = SimpleTaskGenerator.generate({
        capability: 'training_coordination',
        context: businessContext,
        input: {
          prompt: 'Coordinate customer training program',
          data: {
            customerAccount: accountResult.result.data,
            trainingRequirements: {
              userCount: 15,
              roles: ['admin', 'user', 'analyst'],
              timeline: '2 weeks',
              format: 'hybrid'
            }
          },
          parameters: {
            scheduleTraining: true,
            prepareContent: true,
            assignTrainers: true
          }
        },
        metadata: { workflowId, step: 'training_coordination' }
      });

      const trainingResult = await testEnv.orchestrator.executeTask(trainingTask, businessContext);
      expect(trainingResult.status).toBe('completed');

      // Step 3: Success Metrics and Monitoring Setup
      const monitoringTask = SimpleTaskGenerator.generate({
        capability: 'success_monitoring',
        context: businessContext,
        input: {
          prompt: 'Set up customer success monitoring',
          data: {
            customerData: trainingResult.result.data,
            successMetrics: {
              adoption: 'user_activity',
              engagement: 'feature_usage',
              satisfaction: 'nps_score',
              value: 'roi_measurement'
            }
          },
          parameters: {
            setupDashboards: true,
            scheduleCheckIns: true,
            defineAlerts: true
          }
        },
        metadata: { workflowId, step: 'success_monitoring' }
      });

      const monitoringResult = await testEnv.orchestrator.executeTask(monitoringTask, businessContext);
      expect(monitoringResult.status).toBe('completed');

      // Verify onboarding workflow
      const onboardingResults = [accountResult, trainingResult, monitoringResult];
      onboardingResults.forEach(result => {
        expect(result.status).toBe('completed');
        expect(result.metadata?.workflowId).toBe(workflowId);
      });
    });
  });

  describe('Financial and Operations Workflows', () => {
    it('should execute monthly financial reporting workflow', async () => {
      const workflowId = 'monthly-financial-report-001';
      const reportingPeriod = '2024-Q1';

      performanceMonitor.start();

      // Step 1: Data Collection and Validation
      const dataCollectionTask = SimpleTaskGenerator.generate({
        capability: 'data_collection',
        context: businessContext,
        input: {
          prompt: 'Collect and validate financial data for monthly reporting',
          data: {
            period: reportingPeriod,
            sources: ['accounting_system', 'crm', 'payroll', 'expenses'],
            validationRules: {
              balanceSheetCheck: true,
              incomeStatementValidation: true,
              crossReferenceVerification: true
            }
          },
          parameters: {
            includeComparisons: true,
            validateIntegrity: true,
            flagAnomalies: true
          }
        },
        metadata: { workflowId, step: 'data_collection', period: reportingPeriod }
      });

      const dataResult = await testEnv.orchestrator.executeTask(dataCollectionTask, businessContext);
      expect(dataResult.status).toBe('completed');

      // Step 2: Financial Analysis and Insights
      const analysisTask = SimpleTaskGenerator.generate({
        capability: 'financial_analysis',
        context: businessContext,
        input: {
          prompt: 'Perform comprehensive financial analysis',
          data: {
            financialData: dataResult.result.data,
            analysisTypes: [
              'revenue_analysis',
              'expense_breakdown',
              'profitability_analysis',
              'cash_flow_analysis',
              'variance_analysis'
            ],
            comparisons: {
              previousPeriod: true,
              budgetVsActual: true,
              yearOverYear: true
            }
          },
          parameters: {
            includeForecasting: true,
            identifyTrends: true,
            generateInsights: true
          }
        },
        metadata: { workflowId, step: 'financial_analysis', period: reportingPeriod }
      });

      const analysisResult = await testEnv.orchestrator.executeTask(analysisTask, businessContext);
      expect(analysisResult.status).toBe('completed');

      // Step 3: Report Generation and Formatting
      const reportGenerationTask = SimpleTaskGenerator.generate({
        capability: 'report_generation',
        context: businessContext,
        input: {
          prompt: 'Generate comprehensive financial report',
          data: {
            analysisResults: analysisResult.result.data,
            reportFormat: {
              executiveSummary: true,
              detailedAnalysis: true,
              visualizations: true,
              recommendations: true,
              appendices: true
            },
            audience: ['executives', 'board', 'investors']
          },
          parameters: {
            includeCharts: true,
            professionalFormatting: true,
            confidentialityMarkings: true
          }
        },
        metadata: { workflowId, step: 'report_generation', period: reportingPeriod }
      });

      const reportResult = await testEnv.orchestrator.executeTask(reportGenerationTask, businessContext);
      expect(reportResult.status).toBe('completed');

      // Step 4: Distribution and Communication
      const distributionTask = SimpleTaskGenerator.generate({
        capability: 'communication_automation',
        context: businessContext,
        input: {
          prompt: 'Distribute financial report to stakeholders',
          data: {
            report: reportResult.result.data,
            distributionList: [
              { group: 'executives', format: 'pdf', delivery: 'email' },
              { group: 'board', format: 'presentation', delivery: 'portal' },
              { group: 'finance_team', format: 'detailed', delivery: 'dashboard' }
            ]
          },
          parameters: {
            scheduleDelivery: true,
            trackDelivery: true,
            enableNotifications: true
          }
        },
        metadata: { workflowId, step: 'distribution', period: reportingPeriod }
      });

      const distributionResult = await testEnv.orchestrator.executeTask(distributionTask, businessContext);
      expect(distributionResult.status).toBe('completed');

      performanceMonitor.end();

      // Verify financial reporting workflow
      const reportingResults = [dataResult, analysisResult, reportResult, distributionResult];

      expect(reportingResults).toHaveLength(4);
      reportingResults.forEach(result => {
        expect(result.status).toBe('completed');
        expect(result.metadata?.workflowId).toBe(workflowId);
        expect(result.metadata?.period).toBe(reportingPeriod);
      });

      // Verify data flow continuity
      expect(analysisResult.result.data).toBeDefined();
      expect(reportResult.result.data).toBeDefined();
      expect(distributionResult.result.data).toBeDefined();

      // Performance validation
      expect(performanceMonitor.getExecutionTime()).toBeLessThan(45000); // 45 seconds
    });

    it('should handle budget planning and approval workflow', async () => {
      const workflowId = 'budget-planning-2024';

      // Step 1: Budget Data Preparation
      const budgetPrepTask = SimpleTaskGenerator.generate({
        capability: 'budget_planning',
        context: businessContext,
        input: {
          prompt: 'Prepare budget data for annual planning',
          data: {
            planningYear: 2024,
            departments: ['sales', 'marketing', 'engineering', 'operations'],
            historicalData: {
              years: [2022, 2023],
              includeActuals: true,
              includeVariances: true
            }
          },
          parameters: {
            includeForecasting: true,
            analyzeGrowthRates: true,
            identifyTrends: true
          }
        },
        metadata: { workflowId, step: 'budget_preparation' }
      });

      const budgetPrepResult = await testEnv.orchestrator.executeTask(budgetPrepTask, businessContext);
      expect(budgetPrepResult.status).toBe('completed');

      // Step 2: Department-Level Budget Creation
      const deptBudgetTask = SimpleTaskGenerator.generate({
        capability: 'departmental_budgeting',
        context: businessContext,
        input: {
          prompt: 'Create departmental budgets based on planning data',
          data: {
            planningData: budgetPrepResult.result.data,
            budgetGuidelines: {
              overallGrowth: 0.15,
              costConstraints: 'moderate',
              investmentPriorities: ['technology', 'talent', 'marketing']
            }
          },
          parameters: {
            collaborativeInput: true,
            scenarioModeling: true,
            riskAssessment: true
          }
        },
        metadata: { workflowId, step: 'departmental_budgeting' }
      });

      const deptBudgetResult = await testEnv.orchestrator.executeTask(deptBudgetTask, businessContext);
      expect(deptBudgetResult.status).toBe('completed');

      // Step 3: Budget Review and Approval Process
      const approvalTask = SimpleTaskGenerator.generate({
        capability: 'approval_workflow',
        context: businessContext,
        input: {
          prompt: 'Process budget through approval workflow',
          data: {
            budgetProposal: deptBudgetResult.result.data,
            approvalChain: [
              { role: 'department_head', required: true },
              { role: 'finance_director', required: true },
              { role: 'cfo', required: true },
              { role: 'ceo', required: true }
            ]
          },
          parameters: {
            enableComments: true,
            trackChanges: true,
            notifyStakeholders: true
          }
        },
        metadata: { workflowId, step: 'budget_approval' }
      });

      const approvalResult = await testEnv.orchestrator.executeTask(approvalTask, businessContext);
      expect(approvalResult.status).toBe('completed');

      // Verify budget planning workflow
      const budgetResults = [budgetPrepResult, deptBudgetResult, approvalResult];
      budgetResults.forEach(result => {
        expect(result.status).toBe('completed');
        expect(result.metadata?.workflowId).toBe(workflowId);
      });
    });
  });

  describe('HR and People Operations Workflows', () => {
    it('should execute employee onboarding workflow', async () => {
      const workflowId = 'employee-onboarding-001';

      // Step 1: Pre-boarding Preparation
      const preboardingTask = SimpleTaskGenerator.generate({
        capability: 'hr_automation',
        context: businessContext,
        input: {
          prompt: 'Prepare for new employee onboarding',
          data: {
            newHire: {
              name: 'Alex Rodriguez',
              position: 'Senior Software Engineer',
              department: 'Engineering',
              startDate: '2024-04-15',
              manager: 'Sarah Kim',
              team: 'Platform Development'
            }
          },
          parameters: {
            setupWorkspace: true,
            prepareDocuments: true,
            scheduleOrientation: true
          }
        },
        metadata: { workflowId, step: 'preboarding' }
      });

      const preboardingResult = await testEnv.orchestrator.executeTask(preboardingTask, businessContext);
      expect(preboardingResult.status).toBe('completed');

      // Step 2: First Day Activities
      const firstDayTask = SimpleTaskGenerator.generate({
        capability: 'onboarding_coordination',
        context: businessContext,
        input: {
          prompt: 'Coordinate first day onboarding activities',
          data: {
            employeeInfo: preboardingResult.result.data,
            firstDaySchedule: {
              orientation: '9:00 AM',
              hrMeeting: '10:30 AM',
              teamIntroduction: '1:00 PM',
              itSetup: '2:30 PM',
              managerMeeting: '4:00 PM'
            }
          },
          parameters: {
            sendNotifications: true,
            trackCompletion: true,
            collectFeedback: true
          }
        },
        metadata: { workflowId, step: 'first_day' }
      });

      const firstDayResult = await testEnv.orchestrator.executeTask(firstDayTask, businessContext);
      expect(firstDayResult.status).toBe('completed');

      // Step 3: 30-60-90 Day Check-ins
      const checkinTask = SimpleTaskGenerator.generate({
        capability: 'employee_development',
        context: businessContext,
        input: {
          prompt: 'Schedule and manage onboarding check-ins',
          data: {
            employeeProgress: firstDayResult.result.data,
            checkinSchedule: {
              day30: { goals: 'basic_productivity', assessment: 'manager_review' },
              day60: { goals: 'full_productivity', assessment: 'peer_feedback' },
              day90: { goals: 'independent_contribution', assessment: 'performance_review' }
            }
          },
          parameters: {
            automateScheduling: true,
            trackMilestones: true,
            generateReports: true
          }
        },
        metadata: { workflowId, step: 'checkin_schedule' }
      });

      const checkinResult = await testEnv.orchestrator.executeTask(checkinTask, businessContext);
      expect(checkinResult.status).toBe('completed');

      // Verify onboarding workflow
      const onboardingResults = [preboardingResult, firstDayResult, checkinResult];
      onboardingResults.forEach(result => {
        expect(result.status).toBe('completed');
        expect(result.metadata?.workflowId).toBe(workflowId);
      });
    });

    it('should handle performance review workflow', async () => {
      const workflowId = 'performance-review-q1-2024';

      // Step 1: Review Preparation and Goal Setting
      const reviewPrepTask = SimpleTaskGenerator.generate({
        capability: 'performance_management',
        context: businessContext,
        input: {
          prompt: 'Prepare performance review process',
          data: {
            reviewPeriod: 'Q1 2024',
            employees: [
              { id: 'emp-001', name: 'John Smith', role: 'Developer' },
              { id: 'emp-002', name: 'Jane Doe', role: 'Designer' },
              { id: 'emp-003', name: 'Mike Johnson', role: 'Manager' }
            ],
            reviewCriteria: {
              goalAchievement: 0.4,
              competencies: 0.3,
              collaboration: 0.2,
              growth: 0.1
            }
          },
          parameters: {
            generateForms: true,
            scheduleReviews: true,
            notifyParticipants: true
          }
        },
        metadata: { workflowId, step: 'review_preparation' }
      });

      const reviewPrepResult = await testEnv.orchestrator.executeTask(reviewPrepTask, businessContext);
      expect(reviewPrepResult.status).toBe('completed');

      // Step 2: 360-Degree Feedback Collection
      const feedbackTask = SimpleTaskGenerator.generate({
        capability: 'feedback_coordination',
        context: businessContext,
        input: {
          prompt: 'Coordinate 360-degree feedback collection',
          data: {
            reviewData: reviewPrepResult.result.data,
            feedbackSources: {
              selfAssessment: true,
              managerReview: true,
              peerFeedback: true,
              directReports: true
            }
          },
          parameters: {
            anonymizeFeedback: true,
            validateResponses: true,
            compileResults: true
          }
        },
        metadata: { workflowId, step: 'feedback_collection' }
      });

      const feedbackResult = await testEnv.orchestrator.executeTask(feedbackTask, businessContext);
      expect(feedbackResult.status).toBe('completed');

      // Step 3: Performance Analysis and Recommendations
      const analysisTask = SimpleTaskGenerator.generate({
        capability: 'performance_analysis',
        context: businessContext,
        input: {
          prompt: 'Analyze performance data and generate recommendations',
          data: {
            feedbackData: feedbackResult.result.data,
            analysisFramework: {
              strengthsWeaknesses: true,
              developmentAreas: true,
              careerPathing: true,
              compensationReview: true
            }
          },
          parameters: {
            generateInsights: true,
            identifyPatterns: true,
            createActionPlans: true
          }
        },
        metadata: { workflowId, step: 'performance_analysis' }
      });

      const analysisResult = await testEnv.orchestrator.executeTask(analysisTask, businessContext);
      expect(analysisResult.status).toBe('completed');

      // Verify performance review workflow
      const reviewResults = [reviewPrepResult, feedbackResult, analysisResult];
      reviewResults.forEach(result => {
        expect(result.status).toBe('completed');
        expect(result.metadata?.workflowId).toBe(workflowId);
      });
    });
  });

  describe('Cross-Functional Integration Workflows', () => {
    it('should execute product launch coordination workflow', async () => {
      const workflowId = 'product-launch-v2.0';
      performanceMonitor.start();

      // Step 1: Pre-launch Planning and Coordination
      const planningTask = SimpleTaskGenerator.generate({
        capability: 'project_coordination',
        context: businessContext,
        input: {
          prompt: 'Coordinate product launch planning across departments',
          data: {
            product: {
              name: 'CoreFlow360 V2.0',
              launchDate: '2024-06-01',
              targetMarket: 'enterprise',
              keyFeatures: ['ai_integration', 'advanced_analytics', 'mobile_app']
            },
            stakeholders: {
              product: ['product_manager', 'ux_designer', 'engineers'],
              marketing: ['marketing_director', 'content_team', 'pr_specialist'],
              sales: ['sales_director', 'sales_engineers', 'customer_success'],
              operations: ['ops_manager', 'support_team', 'qa_team']
            }
          },
          parameters: {
            createTimeline: true,
            assignResponsibilities: true,
            setupTracking: true
          }
        },
        metadata: { workflowId, step: 'launch_planning' }
      });

      const planningResult = await testEnv.orchestrator.executeTask(planningTask, businessContext);
      expect(planningResult.status).toBe('completed');

      // Step 2: Marketing Campaign Development
      const marketingTask = SimpleTaskGenerator.generate({
        capability: 'marketing_automation',
        context: businessContext,
        input: {
          prompt: 'Develop comprehensive marketing campaign for product launch',
          data: {
            launchPlan: planningResult.result.data,
            campaignElements: {
              website: 'landing_page_updates',
              content: 'blogs_whitepapers_case_studies',
              social: 'linkedin_twitter_youtube',
              events: 'webinars_conferences_demos',
              email: 'announcement_nurture_sequences'
            }
          },
          parameters: {
            personalizeContent: true,
            scheduleDelivery: true,
            trackPerformance: true
          }
        },
        metadata: { workflowId, step: 'marketing_campaign' }
      });

      const marketingResult = await testEnv.orchestrator.executeTask(marketingTask, businessContext);
      expect(marketingResult.status).toBe('completed');

      // Step 3: Sales Enablement and Training
      const salesEnablementTask = SimpleTaskGenerator.generate({
        capability: 'sales_enablement',
        context: businessContext,
        input: {
          prompt: 'Enable sales team for product launch',
          data: {
            productInfo: marketingResult.result.data,
            enablementMaterials: {
              battleCards: 'competitive_positioning',
              demos: 'feature_demonstrations',
              pricing: 'packaging_guidelines',
              objectionHandling: 'faq_responses'
            }
          },
          parameters: {
            scheduleTraining: true,
            createCertification: true,
            trackReadiness: true
          }
        },
        metadata: { workflowId, step: 'sales_enablement' }
      });

      const salesResult = await testEnv.orchestrator.executeTask(salesEnablementTask, businessContext);
      expect(salesResult.status).toBe('completed');

      // Step 4: Launch Execution and Monitoring
      const launchTask = SimpleTaskGenerator.generate({
        capability: 'launch_execution',
        context: businessContext,
        input: {
          prompt: 'Execute product launch and monitor performance',
          data: {
            readinessCheck: salesResult.result.data,
            launchActivities: {
              announcement: 'public_announcement',
              availability: 'product_activation',
              support: 'customer_support_ready',
              monitoring: 'performance_tracking'
            }
          },
          parameters: {
            coordinateActivities: true,
            monitorMetrics: true,
            enableRapidResponse: true
          }
        },
        metadata: { workflowId, step: 'launch_execution' }
      });

      const launchResult = await testEnv.orchestrator.executeTask(launchTask, businessContext);
      expect(launchResult.status).toBe('completed');

      performanceMonitor.end();

      // Verify product launch workflow
      const launchResults = [planningResult, marketingResult, salesResult, launchResult];

      expect(launchResults).toHaveLength(4);
      launchResults.forEach(result => {
        expect(result.status).toBe('completed');
        expect(result.metadata?.workflowId).toBe(workflowId);
      });

      // Verify cross-functional coordination
      expect(marketingResult.result.data).toBeDefined();
      expect(salesResult.result.data).toBeDefined();
      expect(launchResult.result.data).toBeDefined();

      // Performance validation for complex workflow
      expect(performanceMonitor.getExecutionTime()).toBeLessThan(60000); // 60 seconds
    });

    it('should handle crisis management workflow', async () => {
      const workflowId = 'crisis-response-001';

      // Step 1: Crisis Detection and Assessment
      const detectionTask = SimpleTaskGenerator.generate({
        capability: 'crisis_management',
        context: businessContext,
        input: {
          prompt: 'Detect and assess business crisis situation',
          data: {
            incident: {
              type: 'data_security_breach',
              severity: 'high',
              affectedSystems: ['customer_database', 'payment_processing'],
              detectedAt: Date.now(),
              reportedBy: 'security_team'
            }
          },
          parameters: {
            assessImpact: true,
            classifySeverity: true,
            identifyStakeholders: true
          }
        },
        metadata: { workflowId, step: 'crisis_detection' }
      });

      const detectionResult = await testEnv.orchestrator.executeTask(detectionTask, businessContext);
      expect(detectionResult.status).toBe('completed');

      // Step 2: Response Team Activation
      const responseTeamTask = SimpleTaskGenerator.generate({
        capability: 'emergency_coordination',
        context: businessContext,
        input: {
          prompt: 'Activate crisis response team and procedures',
          data: {
            crisisAssessment: detectionResult.result.data,
            responseTeam: {
              incident_commander: 'cto',
              security_lead: 'security_director',
              communications: 'communications_director',
              legal: 'legal_counsel',
              customer_success: 'cs_director'
            }
          },
          parameters: {
            notifyTeam: true,
            activateProcedures: true,
            establishCommsChannel: true
          }
        },
        metadata: { workflowId, step: 'response_activation' }
      });

      const responseResult = await testEnv.orchestrator.executeTask(responseTeamTask, businessContext);
      expect(responseResult.status).toBe('completed');

      // Step 3: Stakeholder Communication
      const communicationTask = SimpleTaskGenerator.generate({
        capability: 'crisis_communication',
        context: businessContext,
        input: {
          prompt: 'Manage crisis communications to stakeholders',
          data: {
            responseStatus: responseResult.result.data,
            communicationPlan: {
              internal: ['employees', 'board', 'investors'],
              external: ['customers', 'partners', 'media', 'regulators'],
              messaging: 'transparency_with_caution',
              frequency: 'regular_updates'
            }
          },
          parameters: {
            personalizeMessages: true,
            scheduleUpdates: true,
            monitorResponse: true
          }
        },
        metadata: { workflowId, step: 'crisis_communication' }
      });

      const communicationResult = await testEnv.orchestrator.executeTask(communicationTask, businessContext);
      expect(communicationResult.status).toBe('completed');

      // Verify crisis management workflow
      const crisisResults = [detectionResult, responseResult, communicationResult];
      crisisResults.forEach(result => {
        expect(result.status).toBe('completed');
        expect(result.metadata?.workflowId).toBe(workflowId);
      });
    });
  });

  describe('Workflow Performance and Reliability', () => {
    it('should maintain performance under workflow load', async () => {
      // Execute multiple workflows concurrently
      const concurrentWorkflows = [
        'sales_pipeline_management',
        'customer_support_escalation',
        'inventory_management',
        'financial_reconciliation',
        'compliance_monitoring'
      ];

      performanceMonitor.start();

      const workflowPromises = concurrentWorkflows.map(async (workflowType, index) => {
        const task = SimpleTaskGenerator.generate({
          capability: 'workflow_orchestration',
          context: businessContext,
          input: {
            prompt: `Execute ${workflowType} workflow`,
            data: { workflowType, workflowId: `concurrent-${index}` }
          },
          metadata: { workflowType, concurrent: true }
        });

        return testEnv.orchestrator.executeTask(task, businessContext);
      });

      const results = await Promise.all(workflowPromises);
      performanceMonitor.end();

      // Verify all workflows completed
      expect(results).toHaveLength(5);
      results.forEach(result => {
        expect(result.status).toBe('completed');
        expect(result.metadata?.concurrent).toBe(true);
      });

      // Performance should scale with concurrent workflows
      expect(performanceMonitor.getExecutionTime()).toBeLessThan(20000); // 20 seconds for 5 workflows
    });

    it('should handle workflow failures and recovery', async () => {
      const workflowId = 'failure-recovery-test';

      // Create a workflow with potential failure points
      const riskyWorkflow = [
        { step: 'data_validation', shouldFail: false },
        { step: 'processing', shouldFail: true }, // This step will fail
        { step: 'notification', shouldFail: false },
        { step: 'cleanup', shouldFail: false }
      ];

      const results: (AgentResult | Error)[] = [];

      for (const step of riskyWorkflow) {
        testEnv.orchestrator.shouldFail = step.shouldFail;

        const task = SimpleTaskGenerator.generate({
          capability: 'workflow_step',
          context: businessContext,
          input: {
            prompt: `Execute ${step.step} workflow step`,
            data: { step: step.step, canFail: step.shouldFail }
          },
          metadata: { workflowId, step: step.step }
        });

        try {
          const result = await testEnv.orchestrator.executeTask(task, businessContext);
          results.push(result);
        } catch (error) {
          results.push(error as Error);
        }
      }

      // Reset mock agent
      testEnv.orchestrator.shouldFail = false;

      // Verify failure handling
      expect(results).toHaveLength(4);
      expect(results[0]).toHaveProperty('status', 'completed'); // Step 1 succeeds
      expect(results[1]).toBeInstanceOf(Error); // Step 2 fails
      expect(results[2]).toHaveProperty('status', 'completed'); // Step 3 succeeds
      expect(results[3]).toHaveProperty('status', 'completed'); // Step 4 succeeds
    });
  });
});