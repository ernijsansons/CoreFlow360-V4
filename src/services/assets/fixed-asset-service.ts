/**
 * Fixed Asset Service
 * Asset tracking, depreciation, and lifecycle management
 */

import type { Env } from '../../types/env';

export class FixedAssetService {
  private env: Env;

  constructor(env: Env) {
    this.env = env;
  }

  /**
   * Create fixed asset
   */
  async createAsset(params: {
    businessId: string;
    categoryId: string;
    assetNumber: string;
    name: string;
    purchaseDate: string;
    purchaseCost: number;
    salvageValue: number;
    usefulLifeYears: number;
    depreciationMethod: string;
  }): Promise<string> {
    const assetId = crypto.randomUUID();
    const bookValue = params.purchaseCost;

    await this.env.DB_MAIN.prepare(
      `INSERT INTO fixed_assets (
        id, business_id, category_id, asset_number, name, purchase_date,
        purchase_cost, salvage_value, useful_life_years, depreciation_method,
        book_value
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).bind(
      assetId, params.businessId, params.categoryId, params.assetNumber,
      params.name, params.purchaseDate, params.purchaseCost, params.salvageValue,
      params.usefulLifeYears, params.depreciationMethod, bookValue
    ).run();

    // Generate depreciation schedule
    await this.generateDepreciationSchedule(assetId);

    return assetId;
  }

  /**
   * Generate depreciation schedule
   */
  private async generateDepreciationSchedule(assetId: string): Promise<void> {
    const asset = await this.env.DB_MAIN.prepare(
      'SELECT * FROM fixed_assets WHERE id = ?'
    ).bind(assetId).first<any>();

    if (!asset) return;

    const depreciableAmount = asset.purchase_cost - asset.salvage_value;
    const purchaseDate = new Date(asset.purchase_date);

    if (asset.depreciation_method === 'straight_line') {
      const monthlyDepreciation = depreciableAmount / (asset.useful_life_years * 12);

      for (let i = 0; i < asset.useful_life_years * 12; i++) {
        const periodDate = new Date(purchaseDate);
        periodDate.setMonth(periodDate.getMonth() + i + 1);

        const accumulated = monthlyDepreciation * (i + 1);
        const bookValue = asset.purchase_cost - accumulated;

        await this.env.DB_MAIN.prepare(
          `INSERT INTO depreciation_schedule (
            asset_id, period_date, depreciation_amount, accumulated_depreciation, book_value
          ) VALUES (?, ?, ?, ?, ?)`
        ).bind(
          assetId, periodDate.toISOString(), monthlyDepreciation, accumulated, bookValue
        ).run();
      }
    }
  }

  /**
   * Record depreciation
   */
  async recordDepreciation(assetId: string, periodDate: string): Promise<void> {
    const schedule = await this.env.DB_MAIN.prepare(
      `SELECT * FROM depreciation_schedule
       WHERE asset_id = ? AND period_date = ? AND is_recorded = 0`
    ).bind(assetId, periodDate).first<any>();

    if (!schedule) return;

    // Mark as recorded
    await this.env.DB_MAIN.prepare(
      `UPDATE depreciation_schedule SET is_recorded = 1 WHERE id = ?`
    ).bind(schedule.id).run();

    // Update asset accumulated depreciation
    await this.env.DB_MAIN.prepare(
      `UPDATE fixed_assets
       SET accumulated_depreciation = ?, book_value = ?, updated_at = datetime('now')
       WHERE id = ?`
    ).bind(schedule.accumulated_depreciation, schedule.book_value, assetId).run();
  }

  /**
   * Dispose asset
   */
  async disposeAsset(params: {
    assetId: string;
    disposalDate: string;
    disposalAmount: number;
    disposalMethod: string;
  }): Promise<{ gainLoss: number }> {
    const asset = await this.env.DB_MAIN.prepare(
      'SELECT * FROM fixed_assets WHERE id = ?'
    ).bind(params.assetId).first<any>();

    if (!asset) throw new Error('Asset not found');

    const gainLoss = params.disposalAmount - asset.book_value;

    await this.env.DB_MAIN.prepare(
      `UPDATE fixed_assets
       SET status = 'disposed', disposal_date = ?, disposal_amount = ?,
           disposal_method = ?, updated_at = datetime('now')
       WHERE id = ?`
    ).bind(
      params.disposalDate, params.disposalAmount, params.disposalMethod, params.assetId
    ).run();

    return { gainLoss };
  }
}
