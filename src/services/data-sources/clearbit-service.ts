import type { CompanyEnrichment, ContactEnrichment, RateLimit } from '../../types/enrichment';

export interface ClearbitPersonResponse {
  id: string;
  name: {
    fullName: string;
    givenName: string;
    familyName: string;
  };
  email: string;
  location: string;
  timeZone: string;
  utcOffset: number;
  geo: {
    city: string;
    state: string;
    stateCode: string;
    country: string;
    countryCode: string;
    lat: number;
    lng: number;
  };
  bio: string;
  site: string;
  avatar: string;
  employment: {
    domain: string;
    name: string;
    title: string;
    role: string;
    subRole: string;
    seniority: string;
  };
  facebook: {
    handle: string;
  };
  github: {
    handle: string;
    id: string;
    avatar: string;
    company: string;
    blog: string;
    followers: number;
    following: number;
  };
  twitter: {
    handle: string;
    id: string;
    bio: string;
    followers: number;
    following: number;
    statuses: number;
    favorites: number;
    location: string;
    site: string;
    avatar: string;
  };
  linkedin: {
    handle: string;
  };
  googleplus: {
    handle: string;
  };
  angellist: {
    handle: string;
    id: string;
    bio: string;
    blog: string;
    site: string;
    followers: number;
    avatar: string;
  };
  aboutme: {
    handle: string;
    bio: string;
    avatar: string;
  };
  gravatar: {
    handle: string;
    urls: Array<{
      value: string;
      title: string;
    }>;
    avatar: string;
    avatars: Array<{
      url: string;
      type: string;
    }>;
  };
  fuzzy: boolean;
  emailProvider: boolean;
}

export interface ClearbitCompanyResponse {
  id: string;
  name: string;
  legalName: string;
  domain: string;
  domainAliases: string[];
  url: string;
  site: {
    phoneNumbers: string[];
    emailAddresses: string[];
    facebookHandle: string;
    twitterHandle: string;
    linkedinHandle: string;
    googlePlusHandle: string;
    youTubeHandle: string;
    instagramHandle: string;
    pinterestHandle: string;
    githubHandle: string;
    angelListHandle: string;
    crunchbaseHandle: string;
  };
  category: {
    sector: string;
    industryGroup: string;
    industry: string;
    subIndustry: string;
    sicCode: string;
    naicsCode: string;
  };
  tags: string[];
  description: string;
  foundedYear: number;
  location: string;
  timeZone: string;
  utcOffset: number;
  geo: {
    streetNumber: string;
    streetName: string;
    subPremise: string;
    streetAddress: string;
    city: string;
    postalCode: string;
    state: string;
    stateCode: string;
    country: string;
    countryCode: string;
    lat: number;
    lng: number;
  };
  logo: string;
  facebook: {
    handle: string;
    likes: number;
  };
  linkedin: {
    handle: string;
  };
  twitter: {
    handle: string;
    id: string;
    bio: string;
    followers: number;
    following: number;
    location: string;
    site: string;
    avatar: string;
  };
  crunchbase: {
    handle: string;
  };
  emailProvider: boolean;
  type: string;
  ticker: string;
  identifiers: {
    usEIN: string;
  };
  phone: string;
  metrics: {
    alexaUsRank: number;
    alexaGlobalRank: number;
    trafficRank: string;
    employees: number;
    employeesRange: string;
    marketCap: number;
    raised: number;
    annualRevenue: number;
    estimatedAnnualRevenue: string;
    fiscalYearEnd: number;
  };
  indexedAt: string;
  tech: string[];
  techCategories: string[];
  parent: {
    domain: string;
  };
  ultimateParent: {
    domain: string;
  };
}

export // TODO: Consider splitting ClearbitService into smaller, focused classes
class ClearbitService {
  private apiKey: string;
  private baseUrl = 'https://person-stream.clearbit.com/v2';
  private companyUrl = 'https://company-stream.clearbit.com/v2';

  constructor(apiKey: string) {
    this.apiKey = apiKey;
  }

  async enrichPerson(email: string): Promise<{
    contact: ContactEnrichment | null;
    company: CompanyEnrichment | null;
    rateLimit: RateLimit;
    error?: string;
  }> {
    try {
      const response = await fetch(`${this.baseUrl}/combined/find?email=${encodeURIComponent(email)}`, {
        headers: {
          'Authorization': `Bearer ${this.apiKey}`,
          'Content-Type': 'application/json'
        }
      });

      const rateLimit = this.extractRateLimit(response);

      if (response.status === 202) {
        // Clearbit is processing - return null but no error
        return { contact: null, company: null, rateLimit };
      }

      if (response.status === 404) {
        // Not found - return null but no error
        return { contact: null, company: null, rateLimit };
      }

      if (response.status === 422) {
        return {
          contact: null,
          company: null,
          rateLimit,
          error: 'Invalid email format'
        };
      }

      if (!response.ok) {
        return {
          contact: null,
          company: null,
          rateLimit,
          error: `Clearbit API error: ${response.status} ${response.statusText}`
        };
      }

      const data = await response.json();

      return {
        contact: this.transformPersonData((data as any).person),
        company: this.transformCompanyData((data as any).company),
        rateLimit
      };
    } catch (error: any) {
      return {
        contact: null,
        company: null,
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
      const response = await fetch(`${this.companyUrl}/companies/find?domain=${encodeURIComponent(domain)}`, {
        headers: {
          'Authorization': `Bearer ${this.apiKey}`,
          'Content-Type': 'application/json'
        }
      });

      const rateLimit = this.extractRateLimit(response);

      if (response.status === 202) {
        return { company: null, rateLimit };
      }

      if (response.status === 404) {
        return { company: null, rateLimit };
      }

      if (!response.ok) {
        return {
          company: null,
          rateLimit,
          error: `Clearbit API error: ${response.status} ${response.statusText}`
        };
      }

      const data: ClearbitCompanyResponse = await response.json();

      return {
        company: this.transformCompanyData(data),
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

  async prospectByCompany(domain: string, role?: string, seniority?: string, department?: string): Promise<{
    contacts: ContactEnrichment[];
    rateLimit: RateLimit;
    error?: string;
  }> {
    try {
      const params = new URLSearchParams({ domain });
      if (role) params.append('role', role);
      if (seniority) params.append('seniority', seniority);
      if (department) params.append('department', department);

      const response = await fetch(`${this.baseUrl}/prospector`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${this.apiKey}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(Object.fromEntries(params))
      });

      const rateLimit = this.extractRateLimit(response);

      if (!response.ok) {
        return {
          contacts: [],
          rateLimit,
          error: `Clearbit Prospector error: ${response.status} ${response.statusText}`
        };
      }

      const data = await response.json();

      return {
        contacts: (data as any).map((person: ClearbitPersonResponse) => this.transformPersonData(person)),
        rateLimit
      };
    } catch (error: any) {
      return {
        contacts: [],
        rateLimit: { requests_remaining: 0, reset_time: '', cost_per_request: 0 },
        error: error instanceof Error ? error.message : 'Unknown error'
      };
    }
  }

  private transformPersonData(person: ClearbitPersonResponse | null): ContactEnrichment | null {
    if (!person) return null;

    return {
      full_name: person.name?.fullName,
      first_name: person.name?.givenName,
      last_name: person.name?.familyName,
      email: person.email,
      title: person.employment?.title,
      seniority_level: this.mapSeniority(person.employment?.seniority),
      department: this.mapDepartment(person.employment?.role),

      linkedin_url: person.linkedin?.handle ? `https://linkedin.com/in/${person.linkedin.handle}` : undefined,
      twitter_handle: person.twitter?.handle,
      github_username: person.github?.handle,
      personal_website: person.site,

      location: person.geo ? {
        city: person.geo.city,
        state: person.geo.state,
        country: person.geo.country,
        timezone: person.timeZone
      } : undefined,

      social_activity: this.buildSocialActivity(person),

      email_deliverability: {
        deliverable: !person.emailProvider,
        confidence: person.fuzzy ? 0.7 : 0.95,
        risk_level: person.emailProvider ? 'high' : 'low',
        email_type: person.emailProvider ? 'personal' : 'work',
        mx_record_valid: true,
        smtp_valid: true,
        catch_all: false
      }
    };
  }

  private transformCompanyData(company: ClearbitCompanyResponse | null): CompanyEnrichment | null {
    if (!company) return null;

    return {
      legal_name: company.legalName,
      domain: company.domain,
      website: company.url,
      description: company.description,
      founded_year: company.foundedYear,
      industry: company.category?.industry,
      sub_industry: company.category?.subIndustry,
      sector: company.category?.sector,

      employee_count: company.metrics?.employees,
      employee_range: company.metrics?.employeesRange,
      annual_revenue: company.metrics?.annualRevenue,
      revenue_range: company.metrics?.estimatedAnnualRevenue,

      headquarters: company.geo ? {
        address: company.geo.streetAddress,
        city: company.geo.city,
        state: company.geo.state,
        country: company.geo.country,
        postal_code: company.geo.postalCode,
        coordinates: {
          lat: company.geo.lat,
          lng: company.geo.lng
        }
      } : undefined,

      tech_stack: company.tech ? {
        languages: [],
        frameworks: [],
        databases: [],
        cloud_providers: [],
        tools: company.tech,
        confidence_score: 0.8,
        detected_at: company.indexedAt
      } : undefined,

      logo_url: company.logo,

      social_profiles: {
      
   linkedin: company.site?.linkedinHandle ? `https://linkedin.com/company/${company.site.linkedinHandle}` : undefined,
        twitter: company.site?.twitterHandle ? `https://twitter.com/${company.site.twitterHandle}` : undefined,
        facebook: company.site?.facebookHandle ? `https://facebook.com/${company.site.facebookHandle}` : undefined,
        github: company.site?.githubHandle ? `https://github.com/${company.site.githubHandle}` : undefined,
      
   crunchbase: company.crunchbase?.handle ? `https://crunchbase.com/organization/${company.crunchbase.handle}` : undefined
      },

      phone: company.phone,
      email_patterns: company.site?.emailAddresses || [],

      public_company: !!company.ticker,
      ticker: company.ticker,
      market_cap: company.metrics?.marketCap,
      parent_company: company.parent?.domain,

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

  private buildSocialActivity(person: ClearbitPersonResponse): any {
    const activities = [];

    if (person.twitter) {
      activities.push({
        platform: 'twitter',
        follower_count: person.twitter.followers,
        following_count: person.twitter.following,
        post_frequency: 'unknown',
        engagement_rate: 0,
        last_activity: '',
        verified: false
      });
    }

    if (person.github) {
      activities.push({
        platform: 'github',
        follower_count: person.github.followers,
        following_count: person.github.following,
        post_frequency: 'unknown',
        engagement_rate: 0,
        last_activity: '',
        verified: false
      });
    }

    return activities[0]; // Return first activity or undefined
  }

  private mapSeniority(seniority: string): string {
    const mapping: Record<string, string> = {
      'Executive': 'c_level',
      'VP': 'vp',
      'Director': 'director',
      'Manager': 'manager',
      'Senior': 'team_lead',
      'Individual Contributor': 'individual_contributor'
    };

    return mapping[seniority] || 'individual_contributor';
  }

  private mapDepartment(role: string): string {
    if (!role) return 'other';

    const mapping: Record<string, string> = {
      'Engineering': 'engineering',
      'Sales': 'sales',
      'Marketing': 'marketing',
      'Human Resources': 'hr',
      'Finance': 'finance',
      'Operations': 'operations',
      'Legal': 'legal',
      'Executive': 'executive'
    };

    for (const [key, value] of Object.entries(mapping)) {
      if (role.toLowerCase().includes(key.toLowerCase())) {
        return value;
      }
    }

    return 'other';
  }

  private extractRateLimit(response: Response): RateLimit {
    return {
      requests_remaining: parseInt(response.headers.get('X-RateLimit-Remaining') || '0'),
      reset_time: response.headers.get('X-RateLimit-Reset') || '',
      cost_per_request: 1 // Clearbit typically costs $1 per successful enrichment
    };
  }
}