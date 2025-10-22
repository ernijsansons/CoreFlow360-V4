import type { CompanyEnrichment, ContactEnrichment, RateLimit } from '../../types/enrichment';

export interface ApolloPersonResponse {
  id: string;
  first_name: string;
  last_name: string;
  name: string;
  linkedin_url: string;
  title: string;
  email: string;
  phone_numbers: Array<{
    raw_number: string;
    sanitized_number: string;
    type: string;
    position: number;
    status: string;
  }>;
  employment_history: Array<{
    organization_name: string;
    title: string;
    start_date: string;
    end_date: string;
    current: boolean;
    degree: string;
    description: string;
    emails: string[];
  }>;
  organization: {
    id: string;
    name: string;
    website_url: string;
    blog_url: string;
    angellist_url: string;
    linkedin_url: string;
    twitter_url: string;
    facebook_url: string;
    languages: string[];
    alexa_ranking: number;
    phone: string;
    linkedin_uid: string;
    founded_year: number;
    publicly_traded_symbol: string;
    publicly_traded_exchange: string;
    logo_url: string;
    crunchbase_url: string;
    primary_domain: string;
    industry: string;
    keywords: string[];
    estimated_num_employees: number;
    snippets_loaded: boolean;
    industry_tag_id: string;
    retail_location_count: number;
    stage: string;
    seo_description: string;
    short_description: string;
    annual_revenue: number;
    total_funding: number;
    latest_funding_round_date: string;
    latest_funding_stage: string;
  };
  photo_url: string;
  twitter_url: string;
  github_url: string;
  facebook_url: string;
  extrapolated_email_confidence: number;
  headline: string;
  country: string;
  state: string;
  city: string;
  personal_emails: string[];
  departments: string[];
  subdepartments: string[];
  functions: string[];
  seniority: string;
}

export interface ApolloCompanyResponse {
  id: string;
  name: string;
  website_url: string;
  blog_url: string;
  angellist_url: string;
  linkedin_url: string;
  twitter_url: string;
  facebook_url: string;
  primary_phone: {
    number: string;
    source: string;
  };
  languages: string[];
  alexa_ranking: number;
  phone: string;
  linkedin_uid: string;
  founded_year: number;
  publicly_traded_symbol: string;
  publicly_traded_exchange: string;
  logo_url: string;
  crunchbase_url: string;
  primary_domain: string;
  sanitized_phone: string;
  industry: string;
  keywords: string[];
  estimated_num_employees: number;
  snippets_loaded: boolean;
  industry_tag_id: string;
  retail_location_count: number;
  stage: string;
  seo_description: string;
  short_description: string;
  annual_revenue: number;
  total_funding: number;
  latest_funding_round_date: string;
  latest_funding_stage: string;
  funding_events: Array<{
    id: string;
    date: string;
    news_url: string;
    funding_round_type: string;
    money_raised: number;
    money_raised_currency_code: string;
    investors: string[];
  }>;
  technology_names: string[];
  current_technologies: Array<{
    uid: string;
    name: string;
    category: string;
  }>;
  account_id: string;
  account: {
    id: string;
    domain: string;
    name: string;
    team_id: string;
    organization_id: string;
    account_stage_id: string;
    source: string;
    original_source: string;
    owner_id: string;
    created_at: string;
    phone: string;
    phone_status: string;
    test_predictive_score: number;
    hubspot_id: string;
    salesforce_id: string;
    crm_owner_id: string;
    parent_account_id: string;
    sanitized_phone: string;
    account_playbook_statuses: any[];
    existence_level: string;
    label_ids: any[];
    typed_custom_fields: Record<string, any>;
    modality: string;
    persona: string;
    market: string;
    prospected_by_current_team: any[];
  };
  departmental_head_count: Record<string, number>;
}

export interface ApolloEmailFinderResponse {
  email: string;
  first_name: string;
  last_name: string;
  organization_name: string;
  confidence: number;
  sources: Array<{
    domain: string;
    uri: string;
    extracted_on: string;
    last_seen_on: string;
    still_on_page: boolean;
  }>;
}

export // TODO: Consider splitting ApolloService into smaller, focused classes
class ApolloService {
  private apiKey: string;
  private baseUrl = 'https://api.apollo.io/v1';

  constructor(apiKey: string) {
    this.apiKey = apiKey;
  }

  async searchPeople(query: {
    q_organization_domains?: string[];
    person_titles?: string[];
    person_seniorities?: string[];
    person_departments?: string[];
    person_locations?: string[];
    organization_num_employees_ranges?: string[];
    page?: number;
    per_page?: number;
  }): Promise<{
    contacts: ContactEnrichment[];
    total_entries: number;
    rateLimit: RateLimit;
    error?: string;
  }> {
    try {
      const response = await fetch(`${this.baseUrl}/mixed_people/search`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Cache-Control': 'no-cache',
          'X-Api-Key': this.apiKey
        },
        body: JSON.stringify({
          ...query,
          per_page: query.per_page || 25
        })
      });

      const rateLimit = this.extractRateLimit(response);

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        return {
          contacts: [],
          total_entries: 0,
          rateLimit,
          error: `Apollo API error: ${response.status} ${(errorData as any).error || response.statusText}`
        };
      }

      const data = await response.json();

      return {
        contacts: (data as any).people.map((person: ApolloPersonResponse) => this.transformPersonData(person)),
        total_entries: (data as any).pagination?.total_entries || 0,
        rateLimit
      };
    } catch (error: any) {
      return {
        contacts: [],
        total_entries: 0,
        rateLimit: { requests_remaining: 0, reset_time: '', cost_per_request: 0 },
        error: error instanceof Error ? error.message : 'Unknown error'
      };
    }
  }

  async enrichPerson(email: string): Promise<{
    contact: ContactEnrichment | null;
    rateLimit: RateLimit;
    error?: string;
  }> {
    try {
      const response = await fetch(`${this.baseUrl}/people/match`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Cache-Control': 'no-cache',
          'X-Api-Key': this.apiKey
        },
        body: JSON.stringify({
          email: email
        })
      });

      const rateLimit = this.extractRateLimit(response);

      if (response.status === 404) {
        return { contact: null, rateLimit };
      }

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        return {
          contact: null,
          rateLimit,
          error: `Apollo API error: ${response.status} ${(errorData as any).error || response.statusText}`
        };
      }

      const data = await response.json();

      return {
        contact: this.transformPersonData((data as any).person),
        rateLimit
      };
    } catch (error: any) {
      return {
        contact: null,
        rateLimit: { requests_remaining: 0, reset_time: '', cost_per_request: 0 },
        error: error instanceof Error ? error.message : 'Unknown error'
      };
    }
  }

  async enrichCompany(domain: string): Promise<{
    company: CompanyEnrichment | null;
    rateLimit: RateLimit;
    error?: string;
  }> {
    try {
      const response = await fetch(`${this.baseUrl}/organizations/enrich`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Cache-Control': 'no-cache',
          'X-Api-Key': this.apiKey
        },
        body: JSON.stringify({
          domain: domain
        })
      });

      const rateLimit = this.extractRateLimit(response);

      if (response.status === 404) {
        return { company: null, rateLimit };
      }

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        return {
          company: null,
          rateLimit,
          error: `Apollo API error: ${response.status} ${(errorData as any).error || response.statusText}`
        };
      }

      const data = await response.json();

      return {
        company: this.transformCompanyData((data as any).organization),
        rateLimit
      };
    } catch (error: any) {
      return {
        company: null,
        rateLimit: { requests_remaining: 0, reset_time: '', cost_per_request: 0 },
        error: error instanceof Error ? error.message : 'Unknown error'
      };
    }
  }

  async findEmail(firstName: string, lastName: string, domain: string): Promise<{
    email: string | null;
    confidence: number;
    rateLimit: RateLimit;
    error?: string;
  }> {
    try {
      const response = await fetch(`${this.baseUrl}/emailfinder`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Cache-Control': 'no-cache',
          'X-Api-Key': this.apiKey
        },
        body: JSON.stringify({
          first_name: firstName,
          last_name: lastName,
          domain: domain
        })
      });

      const rateLimit = this.extractRateLimit(response);

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        return {
          email: null,
          confidence: 0,
          rateLimit,
          error: `Apollo API error: ${response.status} ${(errorData as any).error || response.statusText}`
        };
      }

      const data: ApolloEmailFinderResponse = await response.json();

      return {
        email: data.email,
        confidence: data.confidence,
        rateLimit
      };
    } catch (error: any) {
      return {
        email: null,
        confidence: 0,
        rateLimit: { requests_remaining: 0, reset_time: '', cost_per_request: 0 },
        error: error instanceof Error ? error.message : 'Unknown error'
      };
    }
  }

  async searchCompanies(query: {
    q_organization_domains?: string[];
    organization_locations?: string[];
    organization_industries?: string[];
    organization_num_employees_ranges?: string[];
    organization_technologies?: string[];
    page?: number;
    per_page?: number;
  }): Promise<{
    companies: CompanyEnrichment[];
    total_entries: number;
    rateLimit: RateLimit;
    error?: string;
  }> {
    try {
      const response = await fetch(`${this.baseUrl}/mixed_companies/search`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Cache-Control': 'no-cache',
          'X-Api-Key': this.apiKey
        },
        body: JSON.stringify({
          ...query,
          per_page: query.per_page || 25
        })
      });

      const rateLimit = this.extractRateLimit(response);

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        return {
          companies: [],
          total_entries: 0,
          rateLimit,
          error: `Apollo API error: ${response.status} ${(errorData as any).error || response.statusText}`
        };
      }

      const data = await response.json();

      return {
        companies: (data as any).organizations.map((org: ApolloCompanyResponse) => this.transformCompanyData(org)),
        total_entries: (data as any).pagination?.total_entries || 0,
        rateLimit
      };
    } catch (error: any) {
      return {
        companies: [],
        total_entries: 0,
        rateLimit: { requests_remaining: 0, reset_time: '', cost_per_request: 0 },
        error: error instanceof Error ? error.message : 'Unknown error'
      };
    }
  }

  private transformPersonData(person: ApolloPersonResponse): ContactEnrichment {
    return {
      full_name: person.name,
      first_name: person.first_name,
      last_name: person.last_name,
      email: person.email,
      phone: person.phone_numbers?.[0]?.sanitized_number,
      title: person.title,
      seniority_level: this.mapSeniority(person.seniority),
      department: this.mapDepartment(person.departments?.[0]),

      employment_history: person.employment_history?.map((emp: any) => ({
        company: emp.organization_name,
        title: emp.title,
        start_date: emp.start_date,
        end_date: emp.end_date,
        duration_months: this.calculateDurationMonths(emp.start_date, emp.end_date),
        description: emp.description,
        is_current: emp.current
      })),

      linkedin_url: person.linkedin_url,
      twitter_handle: person.twitter_url ? this.extractTwitterHandle(person.twitter_url) : undefined,
      github_username: person.github_url ? this.extractGithubUsername(person.github_url) : undefined,

      location: {
        city: person.city,
        state: person.state,
        country: person.country,
        timezone: ''
      },

      email_deliverability: {
        deliverable: true,
        confidence: person.extrapolated_email_confidence / 100,
        risk_level: person.extrapolated_email_confidence > 80 ? 'low' : 'medium',
        email_type: 'work',
        mx_record_valid: true,
        smtp_valid: true,
        catch_all: false
      },

      skills: person.functions || [],
      personal_email: person.personal_emails?.[0]
    };
  }

  private transformCompanyData(company: ApolloCompanyResponse): CompanyEnrichment {
    return {
      legal_name: company.name,
      domain: company.primary_domain,
      website: company.website_url,
      description: company.short_description,
      founded_year: company.founded_year,
      industry: company.industry,

      employee_count: company.estimated_num_employees,
      employee_range: this.getEmployeeRange(company.estimated_num_employees),
      annual_revenue: company.annual_revenue,
      funding_total: company.total_funding,

      funding_rounds: company.funding_events?.map((event: any) => ({
        round_type: event.funding_round_type,
        amount: event.money_raised,
        currency: event.money_raised_currency_code,
        date: event.date,
        investors: event.investors,
        series: event.funding_round_type
      })),

      tech_stack: {
        languages: [],
        frameworks: [],
        databases: [],
        cloud_providers: [],
        tools: company.technology_names || [],
        confidence_score: 0.9,
        detected_at: new Date().toISOString()
      },

      logo_url: company.logo_url,

      social_profiles: {
        linkedin: company.linkedin_url,
        twitter: company.twitter_url,
        facebook: company.facebook_url,
        angellist: company.angellist_url,
        crunchbase: company.crunchbase_url
      },

      phone: company.phone || company.primary_phone?.number,

      public_company: !!company.publicly_traded_symbol,
      ticker: company.publicly_traded_symbol,

      seo_metrics: {
        domain_authority: 0,
        page_authority: 0,
        organic_traffic: 0,
        organic_keywords: 0,
        backlinks: 0,
        referring_domains: 0
      }
    };
  }

  private mapSeniority(seniority: string): string {
    if (!seniority) return 'individual_contributor';

    const mapping: Record<string, string> = {
      'c_suite': 'c_level',
      'founder': 'founder',
      'vp': 'vp',
      'director': 'director',
      'manager': 'manager',
      'senior': 'team_lead',
      'entry': 'individual_contributor',
      'intern': 'individual_contributor'
    };

    return mapping[seniority.toLowerCase()] || 'individual_contributor';
  }

  private mapDepartment(department: string): string {
    if (!department) return 'other';

    const mapping: Record<string, string> = {
      'engineering': 'engineering',
      'information_technology': 'engineering',
      'sales': 'sales',
      'marketing': 'marketing',
      'human_resources': 'hr',
      'finance': 'finance',
      'operations': 'operations',
      'legal': 'legal',
      'executive': 'executive',
      'administrative': 'operations'
    };

    return mapping[department.toLowerCase()] || 'other';
  }

  private getEmployeeRange(count: number): string {
    if (count <= 10) return '1-10';
    if (count <= 50) return '11-50';
    if (count <= 200) return '51-200';
    if (count <= 500) return '201-500';
    if (count <= 1000) return '501-1000';
    return '1000+';
  }

  private calculateDurationMonths(startDate: string, endDate?: string): number {
    const start = new Date(startDate);
    const end = endDate ? new Date(endDate) : new Date();
    const diffTime = Math.abs(end.getTime() - start.getTime());
    const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
    return Math.floor(diffDays / 30);
  }

  private extractTwitterHandle(url: string): string {
    const match = url.match(/twitter\.com\/([^/?]+)/);
    return match ? match[1] : '';
  }

  private extractGithubUsername(url: string): string {
    const match = url.match(/github\.com\/([^/?]+)/);
    return match ? match[1] : '';
  }

  private extractRateLimit(response: Response): RateLimit {
    return {
      requests_remaining: parseInt(response.headers.get('X-RateLimit-Remaining') || '1000'),
      reset_time: response.headers.get('X-RateLimit-Reset') || '',
      cost_per_request: 1 // Apollo typically costs $1 per credit
    };
  }
}